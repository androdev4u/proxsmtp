/*
 * Copyright (c) 2004, Nate Nielsen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 * CONTRIBUTORS
 *  Nate Nielsen <nielsen@memberwebs.com>
 *  Yamamoto Takao <takao@oakat.org>
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <paths.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "usuals.h"
#include "compat.h"
#include "sock_any.h"
#include "clamsmtpd.h"
#include "util.h"

/* -----------------------------------------------------------------------
 * Structures
 */

typedef struct clamsmtp_thread
{
    pthread_t tid;      /* Written to by the main thread */
    int fd;             /* The file descriptor or -1 */
}
clamsmtp_thread_t;

#define LINE_TOO_LONG(ctx)      ((ctx)->linelen >= (LINE_LENGTH - 2))
#define RETURN(x)               { ret = x; goto cleanup; }

/* -----------------------------------------------------------------------
 * Strings
 */

#define KL(s)               ((sizeof(s) - 1) / sizeof(char))

#define CRLF                "\r\n"

#define SMTP_TOOLONG        "500 Line too long" CRLF
#define SMTP_STARTBUSY      "554 Server Busy" CRLF
#define SMTP_STARTFAILED    "554 Local Error" CRLF
#define SMTP_DATAVIRUS      "550 Virus Detected; Content Rejected" CRLF
#define SMTP_DATAINTERMED   "354 Start mail input; end with <CRLF>.<CRLF>" CRLF
#define SMTP_FAILED         "451 Local Error" CRLF
#define SMTP_NOTSUPP        "502 Command not implemented" CRLF
#define SMTP_DATAVIRUSOK    "250 Virus Detected; Discarded Email" CRLF
#define SMTP_OK             "250 Ok" CRLF

#define SMTP_DATA           "DATA" CRLF
#define SMTP_START          "220 "
#define SMTP_DELIMS         "\r\n\t :"

#define HELO_CMD            "HELO"
#define EHLO_CMD            "EHLO"
#define FROM_CMD            "MAIL FROM"
#define TO_CMD              "RCPT TO"
#define DATA_CMD            "DATA"
#define RSET_CMD            "RSET"

#define DATA_END_SIG        CRLF "." CRLF

#define DATA_RSP            "354"
#define OK_RSP              "250"
#define START_RSP           "220"

#define CLAM_OK             "OK"
#define CLAM_ERROR          "ERROR"
#define CLAM_FOUND          "FOUND"

#define CONNECT_RSP         "PONG"
#define CLAM_SCAN           "SCAN "

#define CLAM_CONNECT        "SESSION\nPING\n"
#define CLAM_DISCONNECT     "END\n"

/* -----------------------------------------------------------------------
 * Default Settings
 */

#define DEFAULT_SOCKET  "10025"
#define DEFAULT_CLAMAV  "/var/run/clamav/clamd"
#define DEFAULT_MAXTHREADS  64
#define DEFAULT_TIMEOUT	180
#define DEFAULT_HEADER  "X-AV-Checked: ClamAV using ClamSMTP\r\n"

/* -----------------------------------------------------------------------
 * Globals
 */

int g_daemonized = 0;                     /* Currently running as a daemon */
int g_debuglevel = LOG_ERR;               /* what gets logged to console */
int g_maxthreads = DEFAULT_MAXTHREADS;    /* The maximum number of threads */
struct timeval g_timeout = { DEFAULT_TIMEOUT, 0 };

struct sockaddr_any g_outaddr;              /* The outgoing address */
const char* g_outname = NULL;
struct sockaddr_any g_clamaddr;             /* Address for connecting to clamd */
const char* g_clamname = DEFAULT_CLAMAV;

const char* g_header = DEFAULT_HEADER;      /* The header to add to email */
const char* g_directory = _PATH_TMP;        /* The directory for temp files */
unsigned int g_unique_id = 0x00100000;      /* For connection ids */
int g_bounce = 0;                           /* Send back a reject line */
int g_quarantine = 0;                       /* Leave virus files in temp dir */

/* For main loop and signal handlers */
int g_quit = 0;

/* The main mutex and condition variables */
pthread_mutex_t g_mutex;
pthread_mutexattr_t g_mutexattr;


/* -----------------------------------------------------------------------
 * Forward Declarations
 */

static usage();
static void on_quit(int signal);
static void pid_file(const char* pid, int write);
static void connection_loop(int sock);
static void* thread_main(void* arg);
static int smtp_passthru(clamsmtp_context_t* ctx);
static int connect_clam(clamsmtp_context_t* ctx);
static int disconnect_clam(clamsmtp_context_t* ctx);
static void add_to_logline(char* logline, char* prefix, char* line);
static int avcheck_data(clamsmtp_context_t* ctx, char* logline);
static int quarantine_virus(clamsmtp_context_t* ctx, char* tempname);
static int complete_data_transfer(clamsmtp_context_t* ctx, const char* tempname);
static int transfer_to_file(clamsmtp_context_t* ctx, char* tempname);
static int transfer_from_file(clamsmtp_context_t* ctx, const char* filename);
static int clam_scan_file(clamsmtp_context_t* ctx, const char* tempname, char* logline);
static int read_server_response(clamsmtp_context_t* ctx);
static void read_junk(clamsmtp_context_t* ctx, int fd);
static int read_line(clamsmtp_context_t* ctx, int* fd, int trim);
static int write_data(clamsmtp_context_t* ctx, int* fd, unsigned char* buf);
static int write_data_raw(clamsmtp_context_t* ctx, int* fd, unsigned char* buf, int len);


int main(int argc, char* argv[])
{
    const char* listensock = DEFAULT_SOCKET;
    clamsmtp_thread_t* threads = NULL;
    struct sockaddr_any addr;
    char* pidfile = NULL;
    int daemonize = 1;
    int sock;
    int true = 1;
    int ch = 0;
    char* t;

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "bc:d:D:h:l:m:p:qt:")) != -1)
    {
        switch(ch)
        {
        /* Actively reject messages */
        case 'b':
            g_bounce = 1;
            break;

        /* Change the CLAM socket */
        case 'c':
            g_clamname = optarg;
            break;

		/*  Don't daemonize  */
        case 'd':
            daemonize = 0;
            g_debuglevel = strtol(optarg, &t, 10);
            if(*t || g_debuglevel > 4)
                errx(1, "invalid debug log level");
            g_debuglevel += LOG_ERR;
            break;

        /* The directory for the files */
        case 'D':
            g_directory = optarg;
            break;

        /* The header to add */
        case 'h':
            if(strlen(optarg) == 0)
                g_header = NULL;
            else
                g_header = optarg;
            break;

        /* Change our listening port */
        case 'l':
            listensock = optarg;
            break;

        /* The maximum number of threads */
        case 'm':
            g_maxthreads = strtol(optarg, &t, 10);
            if(*t || g_maxthreads <= 1 || g_maxthreads >= 1024)
                  errx(1, "invalid max threads (must be between 1 and 1024");
            break;

        /* Write out a pid file */
        case 'p':
            pidfile = optarg;
            break;

        /* The timeout */
		case 't':
			g_timeout.tv_sec = strtol(optarg, &t, 10);
			if(*t || g_timeout.tv_sec <= 0)
				errx(1, "invalid timeout: %s", optarg);
			break;

        /* Leave virus files in directory */
        case 'q':
            g_quarantine = 1;
            break;

        /* Usage information */
        case '?':
        default:
            usage();
            break;
		}
    }

	argc -= optind;
	argv += optind;

    if(argc != 1)
        usage();

    g_outname = argv[0];

    messagex(NULL, LOG_DEBUG, "starting up...");

    /* Parse all the addresses */
    if(sock_any_pton(listensock, &addr, SANY_OPT_DEFANY) == -1)
        errx(1, "invalid listen socket name or ip: %s", listensock);
    if(sock_any_pton(g_outname, &g_outaddr, SANY_OPT_DEFPORT(25)) == -1)
        errx(1, "invalid connect socket name or ip: %s", g_outname);
    if(sock_any_pton(g_clamname, &g_clamaddr, SANY_OPT_DEFLOCAL) == -1)
        errx(1, "invalid clam socket name: %s", g_clamname);

    if(daemonize)
    {
        /* Fork a daemon nicely here */
        if(daemon(0, 0) == -1)
        {
            message(NULL, LOG_ERR, "couldn't run as daemon");
            exit(1);
        }

        messagex(NULL, LOG_DEBUG, "running as a daemon");
        g_daemonized = 1;

        /* Open the system log */
        openlog("clamsmtpd", 0, LOG_MAIL);
    }

    /* Create the socket */
    sock = socket(SANY_TYPE(addr), SOCK_STREAM, 0);
    if(sock < 0)
      err(1, "couldn't open socket");

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true));

    /* Unlink the socket file if it exists */
    if(SANY_TYPE(addr) == AF_UNIX)
        unlink(listensock);

    if(bind(sock, &SANY_ADDR(addr), SANY_LEN(addr)) != 0)
      err(1, "couldn't bind to address: %s", listensock);

    /* Let 5 connections queue up */
    if(listen(sock, 5) != 0)
      err(1, "couldn't listen on socket");

    messagex(NULL, LOG_DEBUG, "created socket: %s", listensock);

    /* Handle some signals */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT,  on_quit);
    signal(SIGTERM, on_quit);

    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    if(pidfile)
        pid_file(pidfile, 1);

    messagex(NULL, LOG_DEBUG, "accepting connections");

    connection_loop(sock);

    if(pidfile)
        pid_file(pidfile, 0);

    messagex(NULL, LOG_DEBUG, "stopped");

    return 0;
}

static void connection_loop(int sock)
{
    clamsmtp_thread_t* threads = NULL;
    struct sockaddr_any addr;
    int fd, i, x, r;

    /* Create the thread buffers */
    threads = (clamsmtp_thread_t*)calloc(g_maxthreads, sizeof(clamsmtp_thread_t));
    if(!threads)
        errx(1, "out of memory");

    /* Create the main mutex and condition variable */
    if(pthread_mutexattr_init(&g_mutexattr) != 0 ||
       pthread_mutexattr_settype(&g_mutexattr, MUTEX_TYPE) ||
       pthread_mutex_init(&g_mutex, &g_mutexattr) != 0)
        errx(1, "threading problem. can't create mutex or condition var");

    /* Now loop and accept the connections */
    while(!g_quit)
    {
        fd = accept(sock, NULL, NULL);
        if(fd == -1)
        {
            switch(errno)
            {
            case EINTR:
            case EAGAIN:
                break;

            case ECONNABORTED:
                message(NULL, LOG_ERR, "couldn't accept a connection");
                break;

            default:
                message(NULL, LOG_ERR, "couldn't accept a connection");
                g_quit = 1;
                break;
            };

            if(g_quit)
                break;

            continue;
        }

        /* Look for thread and also clean up others */
        for(i = 0; i < g_maxthreads; i++)
        {
            /* Find a thread to run or clean up old threads */
            if(threads[i].tid != 0)
            {
                plock();
                    x = threads[i].fd;
                punlock();

                if(x == -1)
                {
                    messagex(NULL, LOG_DEBUG, "cleaning up completed thread");
                    pthread_join(threads[i].tid, NULL);
                    threads[i].tid = 0;
                }
            }

            /* Start a new thread if neccessary */
            if(fd != -1 && threads[i].tid == 0)
            {
                threads[i].fd = fd;
                r = pthread_create(&(threads[i].tid), NULL, thread_main,
                                   (void*)(threads + i));
                if(r != 0)
                {
                    errno = r;
                    message(NULL, LOG_ERR, "couldn't create thread");
                    g_quit = 1;
                    break;
                }

                messagex(NULL, LOG_DEBUG, "created thread for connection");
                fd = -1;
                break;
            }
        }

        /* Check to make sure we have a thread */
        if(fd != -1)
        {
            messagex(NULL, LOG_ERR, "too many connections open (max %d)", g_maxthreads);

            /* TODO: Respond with a too many connections message */
            write_data(NULL, &fd, SMTP_STARTBUSY);
            shutdown(fd, SHUT_RDWR);
        }
    }

    messagex(NULL, LOG_DEBUG, "waiting for threads to quit");

    /* Quit all threads here */
    for(i = 0; i < g_maxthreads; i++)
    {
        /* Clean up quit threads */
        if(threads[i].tid != 0)
        {
            if(threads[i].fd != -1)
                shutdown(threads[i].fd, SHUT_RDWR);

            pthread_join(threads[i].tid, NULL);
        }
    }

    /* Close the mutex */
    pthread_mutex_destroy(&g_mutex);
    pthread_mutexattr_destroy(&g_mutexattr);
}

static void on_quit(int signal)
{
    g_quit = 1;

    /* fprintf(stderr, "clamsmtpd: got signal to quit\n"); */
}

static int usage()
{
    fprintf(stderr, "clamsmtpd [-bq] [-c clamaddr] [-d debuglevel] [-D tmpdir] [-h header] "
            "[-l listenaddr] [-m maxconn] [-p pidfile] [-t timeout] serveraddr\n");
    exit(2);
}

static void pid_file(const char* pidfile, int write)
{
    if(write)
    {
        FILE* f = fopen(pidfile, "w");
        if(f == NULL)
        {
            message(NULL, LOG_ERR, "couldn't open pid file: %s", pidfile);
        }
        else
        {
            fprintf(f, "%d\n", (int)getpid());

            if(ferror(f))
                message(NULL, LOG_ERR, "couldn't write to pid file: %s", pidfile);

            fclose(f);
        }

        messagex(NULL, LOG_DEBUG, "wrote pid file: %s", pidfile);
    }

    else
    {
        unlink(pidfile);
        messagex(NULL, LOG_DEBUG, "removed pid file: %s", pidfile);
    }
}

static void* thread_main(void* arg)
{
    clamsmtp_thread_t* thread = (clamsmtp_thread_t*)arg;
    struct sockaddr_any addr;
    struct sockaddr_any* outaddr;
    const char* outname;
    char buf[MAXPATHLEN];
    clamsmtp_context_t ctx;
    int ret = 0;

    ASSERT(thread);

    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    memset(&ctx, 0, sizeof(ctx));

    /* Assign a unique id to the connection */
    ctx.id = g_unique_id++;

    ctx.server = -1;
    ctx.clam = -1;

    plock();
        ctx.client = thread->fd;
    punlock();

    ASSERT(ctx.client != -1);

    memset(&addr, 0, sizeof(addr));
    SANY_LEN(addr) = sizeof(addr);

    /* Get the peer name */
    if(getpeername(ctx.client, &SANY_ADDR(addr), &SANY_LEN(addr)) == -1 ||
       sock_any_ntop(&addr, buf, MAXPATHLEN, SANY_OPT_NOPORT) == -1)
        message(&ctx, LOG_WARNING, "couldn't get peer address");
    else
        messagex(&ctx, LOG_INFO, "accepted connection from: %s", buf);


    /* Create the server connection address */
    outaddr = &g_outaddr;
    outname = g_outname;

    if(SANY_TYPE(*outaddr) == AF_INET &&
       outaddr->s.in.sin_addr.s_addr == 0)
    {
        /* Use the incoming IP as the default */
        in_addr_t in = addr.s.in.sin_addr.s_addr;
        memcpy(&addr, &g_outaddr, sizeof(addr));
        addr.s.in.sin_addr.s_addr = in;

        outaddr = &addr;

        if(sock_any_ntop(outaddr, buf, MAXPATHLEN, 0) != -1)
            outname = buf;
    }


    /* Connect to the server */
    if((ctx.server = socket(SANY_TYPE(*outaddr), SOCK_STREAM, 0)) < 0 ||
        connect(ctx.server, &SANY_ADDR(*outaddr), SANY_LEN(*outaddr)) < 0)
    {
        message(&ctx, LOG_ERR, "couldn't connect to %s", outname);
        RETURN(-1);
    }

    messagex(&ctx, LOG_DEBUG, "connected to server: %s", outname);


    if(connect_clam(&ctx) == -1)
        RETURN(-1);


    /* call the processor */
    ret = smtp_passthru(&ctx);

cleanup:

    disconnect_clam(&ctx);

    /* Let the client know about fatal errors */
    if(ret == -1 && ctx.client != -1)
       write_data(&ctx, &(ctx.client), SMTP_STARTFAILED);

    if(ctx.client != -1)
    {
        shutdown(ctx.client, SHUT_RDWR);
        messagex(&ctx, LOG_NOTICE, "closed client connection");
    }

    if(ctx.server != -1)
    {
        shutdown(ctx.server, SHUT_RDWR);
        messagex(&ctx, LOG_DEBUG, "closed server connection");
    }

    /* mark this as done */
    plock();
        thread->fd = -1;
    punlock();

    return (void*)(ret == 0 ? 0 : 1);
}

static int smtp_passthru(clamsmtp_context_t* ctx)
{
    char logline[LINE_LENGTH];
    int r, ret = 0;
    int first_rsp = 1;
	fd_set mask;

    ASSERT(ctx->clam != -1 && ctx->server != -1);
    logline[0] = 0;

    for(;;)
    {
		FD_ZERO(&mask);

    	FD_SET(ctx->client, &mask);
    	FD_SET(ctx->server, &mask);

		switch(select(FD_SETSIZE, &mask, NULL, NULL, &g_timeout))
		{
		case 0:
			messagex(ctx, LOG_ERR, "network operation timed out");
            RETURN(-1);
		case -1:
			message(ctx, LOG_ERR, "couldn't select on sockets");
            RETURN(-1);
		};

        /* Client has data available, read a line and process */
        if(FD_ISSET(ctx->client, &mask))
        {
            if(read_line(ctx, &(ctx->client), 0) == -1)
                RETURN(-1);

            /* Client disconnected, we're done */
            if(ctx->linelen == 0)
                RETURN(0);

            /* We don't let clients send really long lines */
            if(LINE_TOO_LONG(ctx))
            {
                if(write_data(ctx, &(ctx->client), SMTP_TOOLONG) == -1)
                    RETURN(-1);

                continue;
            }

            /* Handle the DATA section via our AV checker */
            if(is_first_word(ctx->line, DATA_CMD, KL(DATA_CMD)))
            {
                /* Send back the intermediate response to the client */
                if(write_data(ctx, &(ctx->client), SMTP_DATAINTERMED) == -1)
                    RETURN(-1);

                /*
                 * Now go into avcheck mode. This also handles the eventual
                 * sending of the data to the server, making the av check
                 * transparent
                 */
                if(avcheck_data(ctx, logline) == -1)
                    RETURN(-1);

                /* Print the log out for this email */
                messagex(ctx, LOG_INFO, "%s", logline);

                /* Reset log line */
                logline[0] = 0;

                /* Command handled */
                continue;
            }

            /*
             * We don't support EHLO (ESMTP) because pipelining
             * and other nuances aren't implemented here. In order
             * to keep things reliable we just disable it all.
             */
            else if(is_first_word(ctx->line, EHLO_CMD, KL(EHLO_CMD)))
            {
                messagex(ctx, LOG_DEBUG, "ESMTP not implemented");

                if(write_data(ctx, &(ctx->client), SMTP_NOTSUPP) == -1)
                    RETURN(-1);

                /* Command handled */
                continue;
            }

            /* Append recipients to log line */
            else if((r = check_first_word(ctx->line, FROM_CMD, KL(FROM_CMD), SMTP_DELIMS)) > 0)
                add_to_logline(logline, "from=", ctx->line + r);

            /* Append sender to log line */
            else if((r = check_first_word(ctx->line, TO_CMD, KL(TO_CMD), SMTP_DELIMS)) > 0)
                add_to_logline(logline, "to=", ctx->line + r);

            /* Reset log line */
            else if(is_first_word(ctx->line, RSET_CMD, KL(RSET_CMD)))
                logline[0] = 0;

            /* All other commands just get passed through to server */
            if(write_data(ctx, &(ctx->server), ctx->line) == -1)
                RETURN(-1);

            continue;
        }

        /* Server has data available, read a line and forward */
        if(FD_ISSET(ctx->server, &mask))
        {
            if(read_line(ctx, &(ctx->server), 0) == -1)
                RETURN(-1);

            if(ctx->linelen == 0)
                RETURN(0);

            if(LINE_TOO_LONG(ctx))
                messagex(ctx, LOG_WARNING, "SMTP response line too long. discarded extra");

            /*
             * We intercept the first response we get from the server.
             * This allows us to change header so that it doesn't look
             * to the client server that we're in a wierd loop.
             */
            if(first_rsp)
            {
                first_rsp = 0;

                if(is_first_word(ctx->line, START_RSP, KL(START_RSP)))
                {
                    messagex(ctx, LOG_DEBUG, "intercepting initial response");

                    strlcpy(ctx->line, SMTP_START, LINE_LENGTH);

                    r = KL(SMTP_START);

                    if(gethostname(ctx->line + r, LINE_LENGTH - r) == -1)
                        strlcat(ctx->line, "clamsmtp", LINE_LENGTH);

                    strlcat(ctx->line, CRLF, LINE_LENGTH);
                    ctx->line[LINE_LENGTH - 1] = 0;

                    if(write_data(ctx, &(ctx->client), ctx->line) == -1)
                        RETURN(-1);

                    /* Command handled */
                    continue;
                }
            }

            if(write_data(ctx, &(ctx->client), ctx->line) == -1)
                RETURN(-1);

            continue;
        }
    }

cleanup:

    if(ret == -1 && ctx->client != -1)
       write_data(ctx, &(ctx->client), SMTP_FAILED);

    return ret;
}

static void add_to_logline(char* logline, char* prefix, char* line)
{
    int l = strlen(logline);
    char* t = logline;

    /* Simple optimization */
    logline += l;
    l = LINE_LENGTH - l;

    ASSERT(l >= 0);

    if(t[0] != 0)
        strlcat(logline, ", ", l);

    strlcat(logline, prefix, l);

    /* Skip initial white space */
    while(*line && isspace(*line))
        *line++;

    strlcat(logline, line, l);
    t = logline + strlen(logline);

    /* Skip later white space */
    while(t > logline && isspace(*(t - 1)))
        *(--t) = 0;
}

static int connect_clam(clamsmtp_context_t* ctx)
{
    int r, len = -1;
    int ret = 0;

    ASSERT(ctx);
    ASSERT(ctx->clam == -1);

    if((ctx->clam = socket(SANY_TYPE(g_clamaddr), SOCK_STREAM, 0)) < 0 ||
       connect(ctx->clam, &SANY_ADDR(g_clamaddr), SANY_LEN(g_clamaddr)) < 0)
    {
        message(ctx, LOG_ERR, "couldn't connect to clamd at %s", g_clamname);
        RETURN(-1);
    }

    read_junk(ctx, ctx->clam);

    /* Send a session and a check header to ClamAV */

    if(write_data(ctx, &(ctx->clam), "SESSION\n") == -1)
        RETURN(-1);

    read_junk(ctx, ctx->clam);
/*
    if(write_data(ctx, &(ctx->clam), "PING\n") == -1 ||
       read_line(ctx, &(ctx->clam), 1) == -1)
        RETURN(-1);

    if(strcmp(ctx->line, CONNECT_RESPONSE) != 0)
    {
        message(ctx, LOG_ERR, "clamd sent an unexpected response: %s", ctx->line);
        RETURN(-1);
    }
*/
    messagex(ctx, LOG_DEBUG, "connected to clamd: %s", g_clamname);

cleanup:

    if(ret < 0)
    {
        if(ctx->clam != -1)
        {
            shutdown(ctx->clam, SHUT_RDWR);
            ctx->clam = -1;
        }
    }

    return ret;
}

static int disconnect_clam(clamsmtp_context_t* ctx)
{
    if(ctx->clam == -1)
        return 0;

    if(write_data(ctx, &(ctx->clam), CLAM_DISCONNECT) != -1)
        read_junk(ctx, ctx->clam);

    shutdown(ctx->clam, SHUT_RDWR);
    messagex(ctx, LOG_DEBUG, "disconnected from clamd");
    ctx->clam = -1;
    return 0;
}

static int clam_scan_file(clamsmtp_context_t* ctx, const char* tempname, char* logline)
{
    int len;

    ASSERT(LINE_LENGTH > MAXPATHLEN + 32);

    strcpy(ctx->line, CLAM_SCAN);
    strcat(ctx->line, tempname);
    strcat(ctx->line, "\n");

    if(write_data(ctx, &(ctx->clam), ctx->line) == -1)
        return -1;

    len = read_line(ctx, &(ctx->clam), 1);
    if(len == 0)
    {
        messagex(ctx, LOG_ERR, "clamd disconnected unexpectedly");
        return -1;
    }

    if(is_last_word(ctx->line, CLAM_OK, KL(CLAM_OK)))
    {
        add_to_logline(logline, "status=", "CLEAN");
        messagex(ctx, LOG_DEBUG, "no virus");
        return 0;
    }

    if(is_last_word(ctx->line, CLAM_FOUND, KL(CLAM_FOUND)))
    {
        len = strlen(tempname);

        if(ctx->linelen > len)
            add_to_logline(logline, "status=VIRUS:", ctx->line + len + 1);
        else
            add_to_logline(logline, "status=", "VIRUS");

        messagex(ctx, LOG_DEBUG, "found virus");
        return 1;
    }

    if(is_last_word(ctx->line, CLAM_ERROR, KL(CLAM_ERROR)))
    {
        messagex(ctx, LOG_ERR, "clamav error: %s", ctx->line);
        return -1;
    }

    messagex(ctx, LOG_ERR, "unexepected response from clamd: %s", ctx->line);
    return -1;
}

static int avcheck_data(clamsmtp_context_t* ctx, char* logline)
{
    /*
     * Note that most failures are non fatal in this function.
     * We only return -1 for data connection errors and the like,
     * For most others we actually send a response back to the
     * client letting them know what happened and let the SMTP
     * connection continue.
     */

    char buf[MAXPATHLEN];
    int havefile = 0;
    int r, ret = 0;

    strlcpy(buf, g_directory, MAXPATHLEN);
    strlcat(buf, "/clamsmtpd.XXXXXX", MAXPATHLEN);

    /* transfer_to_file deletes the temp file on failure */
    if((r = transfer_to_file(ctx, buf)) > 0)
    {
        havefile = 1;
        r = clam_scan_file(ctx, buf, logline);
    }

    switch(r)
    {

    /*
     * There was an error tell the client. We haven't notified
     * the server about any of this yet
     */
    case -1:
        if(write_data(ctx, &(ctx->client), SMTP_FAILED))
            RETURN(-1);
        break;

    /*
     * No virus was found. Now we initiate a connection to the server
     * and transfer the file to it.
     */
    case 0:
        if(complete_data_transfer(ctx, buf) == -1)
            RETURN(-1);
        break;

    /*
     * A virus was found, normally we just drop the email. But if
     * requested we can send a simple message back to our client.
     * The server doesn't know data was ever sent, and the client can
     * choose to reset the connection to reuse it if it wants.
     */
    case 1:
        if(write_data(ctx, &(ctx->client),
                   g_bounce ? SMTP_DATAVIRUS : SMTP_DATAVIRUSOK) == -1)
            RETURN(-1);

        /* Any special post operation actions on the virus */
        quarantine_virus(ctx, buf);
        break;

    default:
        ASSERT(0 && "Invalid clam_scan_file return value");
        break;
    };

cleanup:
    if(havefile)
    {
        messagex(ctx, LOG_DEBUG, "deleting temporary file: %s", buf);
        unlink(buf);
    }

    return ret;
}

static int complete_data_transfer(clamsmtp_context_t* ctx, const char* tempname)
{
    ASSERT(ctx);
    ASSERT(tempname);

    /* Ask the server for permission to send data */
    if(write_data(ctx, &(ctx->server), SMTP_DATA) == -1)
        return -1;

    if(read_server_response(ctx) == -1)
        return -1;

    /* If server returns an error then tell the client */
    if(!is_first_word(ctx->line, DATA_RSP, KL(DATA_RSP)))
    {
        if(write_data(ctx, &(ctx->client), ctx->line) == -1)
            return -1;

        messagex(ctx, LOG_DEBUG, "server refused data transfer");

        return 0;
    }

    /* Now pull up the file and send it to the server */
    if(transfer_from_file(ctx, tempname) == -1)
    {
        /* Tell the client it went wrong */
        write_data(ctx, &(ctx->client), SMTP_FAILED);
        return -1;
    }

    /* Okay read the response from the server and echo it to the client */
    if(read_server_response(ctx) == -1)
        return -1;

    if(write_data(ctx, &(ctx->client), ctx->line) == -1)
        return -1;

    return 0;
}

static int quarantine_virus(clamsmtp_context_t* ctx, char* tempname)
{
    char buf[MAXPATHLEN];
    char* t;

    if(!g_quarantine)
        return 0;

    strlcpy(buf, g_directory, MAXPATHLEN);
    strlcat(buf, "/virus.", MAXPATHLEN);

    /* Points to null terminator */
    t = buf + strlen(buf);

    /*
     * Yes, I know we're using mktemp. And yet we're doing it in
     * a safe manner due to the link command below not overwriting
     * existing files.
     */
    for(;;)
    {
        /* Null terminate off the ending, and replace with X's for mktemp */
        *t = 0;
        strlcat(buf, "XXXXXX", MAXPATHLEN);

        if(!mktemp(buf))
        {
            message(ctx, LOG_ERR, "couldn't create quarantine file name");
            return -1;
        }

        /* Try to link the file over to the temp */
        if(link(tempname, buf) == -1)
        {
            /* We don't want to allow race conditions */
            if(errno == EEXIST)
            {
                message(ctx, LOG_WARNING, "race condition when quarantining virus file: %s", buf);
                continue;
            }

            message(ctx, LOG_ERR, "couldn't quarantine virus file");
            return -1;
        }

        break;
    }

    messagex(ctx, LOG_INFO, "quarantined virus file as: %s", buf);
    return 0;
}

static int transfer_to_file(clamsmtp_context_t* ctx, char* tempname)
{
    /* If there aren't any lines in the message and just an
       end signature then start at the dot. */
    const char* topsig = strchr(DATA_END_SIG, '.');
    const char* cursig = topsig;
    FILE* tfile = NULL;
    int tfd = -1;
    int ret = 0;
    char ch;
    int count = 0;

    ASSERT(topsig != NULL);

    if((tfd = mkstemp(tempname)) == -1 ||
       (tfile = fdopen(tfd, "w")) == NULL)
    {
        message(ctx, LOG_ERR, "couldn't open temp file");
        RETURN(-1);
    }

    messagex(ctx, LOG_DEBUG, "created temporary file: %s", tempname);

    for(;;)
    {
        switch(read(ctx->client, &ch, 1))
        {
        case 0:
            messagex(ctx, LOG_ERR, "unexpected end of data from client");
            RETURN(-1);

        case -1:
            message(ctx, LOG_ERR, "error reading from client");
            RETURN(-1);
        };

        if((char)ch != *cursig)
        {
            /* Write out the part of the sig we kept back */
            if(cursig != topsig)
            {
                /* We check errors on this later */
                fwrite(topsig, 1, cursig - topsig, tfile);
                count += (cursig - topsig);
            }

            /* We've seen at least one char not in the sig */
            cursig = topsig = DATA_END_SIG;
        }

        /* The sig may have been reset above so check again */
        if((char)ch == *cursig)
        {
            cursig++;

            if(!*cursig)
            {
                /* We found end of data */
                break;
            }
        }

        else
        {
            fputc(ch, tfile);
            count++;
        }
    }

    if(ferror(tfile))
    {
        message(ctx, LOG_ERR, "error writing to temp file: %s", tempname);
        RETURN(-1);
    }

    ret = count;
    messagex(ctx, LOG_DEBUG, "wrote %d bytes to temp file", count);

cleanup:

    if(tfile)
       fclose(tfile);

    if(tfd != -1)
    {
        /* Only close this if not opened as a stream */
        if(tfile == NULL)
            close(tfd);

        if(ret == -1)
        {
            messagex(ctx, LOG_DEBUG, "discarding temporary file");
            unlink(tempname);
        }
    }

    return ret;
}

static int transfer_from_file(clamsmtp_context_t* ctx, const char* filename)
{
    FILE* file = NULL;
    const char* t;
    const char* e;
    int header = 0;
    int ret = 0;
    int len, r;

    file = fopen(filename, "r");
    if(file == NULL)
    {
        message(ctx, LOG_ERR, "couldn't open temporary file: %s", filename);
        RETURN(-1);
    }

    messagex(ctx, LOG_DEBUG, "opened temporary file: %s", filename);

    while(fgets(ctx->line, LINE_LENGTH, file) != NULL)
    {
        if(g_header && !header)
        {
            /*
             * The first blank line we see means the headers are done.
             * At this point we add in our virus checked header.
             */
            if(is_blank_line(ctx->line))
            {
                if(write_data_raw(ctx, &(ctx->server), (char*)g_header,
                                  strlen(g_header)) == -1)
                    RETURN(-1);

                header = 1;
            }
        }

        if(write_data_raw(ctx, &(ctx->server), ctx->line, strlen(ctx->line)) == -1)
            RETURN(-1);
    }

    if(ferror(file))
    {
        message(ctx, LOG_ERR, "error reading temporary file: %s", filename);
        RETURN(-1);
    }

    if(write_data(ctx, &(ctx->server), DATA_END_SIG) == -1)
        RETURN(-1);

    messagex(ctx, LOG_DEBUG, "sent email data");

cleanup:

    if(file != NULL)
        fclose(file);

    return ret;
}

static int read_server_response(clamsmtp_context_t* ctx)
{
    /* Read response line from the server */
    if(read_line(ctx, &(ctx->server), 0) == -1)
        return -1;

    if(ctx->linelen == 0)
    {
        messagex(ctx, LOG_ERR, "server disconnected unexpectedly");

        /* Tell the client it went wrong */
        write_data(ctx, &(ctx->client), SMTP_FAILED);
        return 0;
    }

    if(LINE_TOO_LONG(ctx))
        messagex(ctx, LOG_WARNING, "SMTP response line too long. discarded extra");

    return 0;
}

static void read_junk(clamsmtp_context_t* ctx, int fd)
{
    char buf[16];
    const char* t;
    int said = 0;
    int l;

    if(fd == -1)
        return;

    /* Make it non blocking */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    for(;;)
    {
        l = read(fd, buf, sizeof(buf) - 1);
        if(l <= 0)
            break;

        buf[l] = 0;
        t = buf;

        while(*t && isspace(*t))
            t++;

        if(!said && *t)
        {
            messagex(ctx, LOG_DEBUG, "received junk data from daemon");
            said = 1;
        }
    }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
}

static int read_line(clamsmtp_context_t* ctx, int* fd, int trim)
{
    int l;
    char* t;
    const char* e;

    if(*fd == -1)
    {
        messagex(ctx, LOG_WARNING, "tried to read from a closed connection");
        return 0;
    }

    ctx->line[0] = 0;
    e = ctx->line + (LINE_LENGTH - 1);

    for(t = ctx->line; t < e; ++t)
    {
        l = read(*fd, (void*)t, sizeof(char));

        /* We got a character */
        if(l == 1)
        {
            /* End of line */
            if(*t == '\n')
            {
                ++t;
                break;
            }

            /* We skip spaces at the beginning if trimming */
            if(trim && t == ctx->line && isspace(*t))
                continue;
        }

        /* If it's the end of file then return that */
        else if(l == 0)
        {
            /* Put in an extra line if there was anything */
            if(t > ctx->line && !trim)
            {
                *t = '\n';
                ++t;
            }

            break;
        }

        /* Transient errors */
        else if(l == -1 && errno == EAGAIN)
            continue;

        /* Fatal errors */
        else if(l == -1)
        {
            message(ctx, LOG_ERR, "couldn't read data");
            return -1;
        }
    }

    *t = 0;

    if(trim)
    {
        while(t > ctx->line && isspace(*(t - 1)))
        {
            --t;
            *t = 0;
        }
    }

    ctx->linelen = t - ctx->line;
    log_fd_data(ctx, ctx->line, fd, 1);

    return ctx->linelen;
}

static int write_data_raw(clamsmtp_context_t* ctx, int* fd, unsigned char* buf, int len)
{
    int r;

    while(len > 0)
    {
        r = write(*fd, buf, len);

        if(r > 0)
        {
            buf += r;
            len -= r;
        }

        else if(r == -1)
        {
            if(errno == EAGAIN)
                continue;

            if(errno == EPIPE)
            {
                shutdown(*fd, SHUT_RDWR);
                *fd = -1;
            }

            message(ctx, LOG_ERR, "couldn't write data to socket");
            return -1;
        }
    }

    return 0;
}

static int write_data(clamsmtp_context_t* ctx, int* fd, unsigned char* buf)
{
    int len = strlen(buf);

    if(*fd == -1)
    {
        message(ctx, LOG_ERR, "connection closed. can't write data.");
        return -1;
    }

    log_fd_data(ctx, buf, fd, 0);
    return write_data_raw(ctx, fd, buf, len);
}
