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

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <err.h>

#include "usuals.h"
#include "compat.h"
#include "sock_any.h"
#include "clamsmtpd.h"
#include "util.h"

/* -----------------------------------------------------------------------
 *  STRUCTURES
 */

typedef struct clamsmtp_thread
{
    pthread_t tid;      /* Written to by the main thread */
    int fd;             /* The file descriptor or -1 */
}
clamsmtp_thread_t;

/* -----------------------------------------------------------------------
 *  STRINGS
 */

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
#define SMTP_BANNER         "220 clamsmtp" CRLF
#define SMTP_HELO_RSP       "250 clamsmtp" CRLF
#define SMTP_EHLO_RSP       "250-clamsmtp" CRLF
#define SMTP_DELIMS         "\r\n\t :"
#define SMTP_MULTI_DELIMS   " -"

#define ESMTP_PIPELINE      "PIPELINING"
#define ESMTP_TLS           "STARTTLS"
#define ESMTP_CHUNK         "CHUNKING"
#define ESMTP_BINARY        "BINARYMIME"
#define ESMTP_CHECK         "CHECKPOINT"

#define HELO_CMD            "HELO"
#define EHLO_CMD            "EHLO"
#define FROM_CMD            "MAIL FROM"
#define TO_CMD              "RCPT TO"
#define DATA_CMD            "DATA"
#define RSET_CMD            "RSET"
#define STARTTLS_CMD        "STARTTLS"
#define BDAT_CMD            "BDAT"

#define DATA_END_SIG        "." CRLF

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

#define DEFAULT_CONFIG      CONF_PREFIX "/httpauthd.conf"

/* -----------------------------------------------------------------------
 *  GLOBALS
 */

clstate_t g_state;                          /* The state and configuration of the daemon */
unsigned int g_unique_id = 0x00100000;      /* For connection ids */


/* -----------------------------------------------------------------------
 *  FORWARD DECLARATIONS
 */

static void usage();
static void on_quit(int signal);
static void pid_file(int write);
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


/* ----------------------------------------------------------------------------------
 *  STARTUP ETC...
 */

int main(int argc, char* argv[])
{
    const char* configfile = DEFAULT_CONFIG;
    int warnargs = 0;
    int sock;
    int true = 1;
    int ch = 0;
    char* t;

    clstate_init(&g_state);

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "bc:d:D:h:l:m:p:qt:v")) != -1)
    {
        switch(ch)
        {
        /* Actively reject messages */
        case 'b':
            g_state.bounce = 1;
            warnargs = 1;
            break;

        /* Change the CLAM socket */
        case 'c':
            g_state.clamname = optarg;
            warnargs = 1;
            break;

		/*  Don't daemonize  */
        case 'd':
            g_state.debug_level = strtol(optarg, &t, 10);
            if(*t) /* parse error */
                errx(1, "invalid debug log level");
            g_state.debug_level += LOG_ERR;
            break;

        /* The directory for the files */
        case 'D':
            g_state.directory = optarg;
            warnargs = 1;
            break;

        /* The configuration file */
        case 'f':
            configfile = optarg;
            break;

        /* The header to add */
        case 'h':
            if(strlen(optarg) == 0)
                g_state.header = NULL;
            else
                g_state.header = optarg;
            warnargs = 1;
            break;

        /* Change our listening port */
        case 'l':
            g_state.listenname = optarg;
            warnargs = 1;
            break;

        /* The maximum number of threads */
        case 'm':
            g_state.max_threads = strtol(optarg, &t, 10);
            if(*t) /* parse error */
                errx(1, "invalid max threads");
            warnargs = 1;
            break;

        /* Write out a pid file */
        case 'p':
            g_state.pidfile = optarg;
            break;

        /* The timeout */
		case 't':
			g_state.timeout.tv_sec = strtol(optarg, &t, 10);
			if(*t) /* parse error */
				errx(1, "invalid timeout");
            warnargs = 1;
			break;

        /* Leave virus files in directory */
        case 'q':
            g_state.quarantine = 1;
            break;

        /* Print version number */
        case 'v':
            printf("clamsmtpd (version %s)\n", VERSION);
            exit(0);
            break;

        /* Leave all files in the tmp directory */
        case 'X':
            g_state.debug_files = 1;
            warnargs = 1;
            break;

        /* Usage information */
        case '?':
        default:
            usage();
            break;
		}
    }

    if(warnargs);
        warnx("please use configuration file instead of command-line flags: %s", configfile);

	argc -= optind;
	argv += optind;

    if(argc > 1)
        usage();
    if(argc == 1)
        g_state.outname = argv[0];

    /* Now parse the configuration file */
    if(clstate_parse_config(&g_state, configfile) == -1)
    {
        /* Only error when it was forced */
        if(configfile != DEFAULT_CONFIG)
            err(1, "couldn't open config file: %s", configfile);
        else
            warnx("default configuration file not found: %s", configfile);
    }

    clstate_validate(&g_state);

    messagex(NULL, LOG_DEBUG, "starting up...");

    /* When set to this we daemonize */
    if(g_state.debug_level == -1)
    {
        /* Fork a daemon nicely here */
        if(daemon(0, 0) == -1)
        {
            message(NULL, LOG_ERR, "couldn't run as daemon");
            exit(1);
        }

        messagex(NULL, LOG_DEBUG, "running as a daemon");
        g_state.daemonized = 1;

        /* Open the system log */
        openlog("clamsmtpd", 0, LOG_MAIL);
    }

    /* Create the socket */
    sock = socket(SANY_TYPE(g_state.listenaddr), SOCK_STREAM, 0);
    if(sock < 0)
    {
        message(NULL, LOG_CRIT, "couldn't open socket");
        exit(1);
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true));

    /* Unlink the socket file if it exists */
    if(SANY_TYPE(g_state.listenaddr) == AF_UNIX)
        unlink(g_state.listenname);

    if(bind(sock, &SANY_ADDR(g_state.listenaddr), SANY_LEN(g_state.listenaddr)) != 0)
    {
        message(NULL, LOG_CRIT, "couldn't bind to address: %s", g_state.listenname);
        exit(1);
    }

    /* Let 5 connections queue up */
    if(listen(sock, 5) != 0)
    {
        message(NULL, LOG_CRIT, "couldn't listen on socket");
        exit(1);
    }

    messagex(NULL, LOG_DEBUG, "created socket: %s", g_state.listenname);

    /* Handle some signals */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGINT,  on_quit);
    signal(SIGTERM, on_quit);

    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    if(g_state.pidfile)
        pid_file(1);

    messagex(NULL, LOG_DEBUG, "accepting connections");

    connection_loop(sock);

    if(g_state.pidfile)
        pid_file(0);

    clstate_cleanup(&g_state);
    messagex(NULL, LOG_DEBUG, "stopped");

    return 0;
}

static void on_quit(int signal)
{
    g_state.quit = 1;
    /* fprintf(stderr, "clamsmtpd: got signal to quit\n"); */
}

static void usage()
{
    fprintf(stderr, "usage: clamsmtpd [-d debuglevel] [-f configfile] \n");
    fprintf(stderr, "       clamsmtpd -v\n");
    exit(2);
}

static void pid_file(int write)
{
    if(write)
    {
        FILE* f = fopen(g_state.pidfile, "w");
        if(f == NULL)
        {
            message(NULL, LOG_ERR, "couldn't open pid file: %s", g_state.pidfile);
        }
        else
        {
            fprintf(f, "%d\n", (int)getpid());

            if(ferror(f))
                message(NULL, LOG_ERR, "couldn't write to pid file: %s", g_state.pidfile);

            fclose(f);
        }

        messagex(NULL, LOG_DEBUG, "wrote pid file: %s", g_state.pidfile);
    }

    else
    {
        unlink(g_state.pidfile);
        messagex(NULL, LOG_DEBUG, "removed pid file: %s", g_state.pidfile);
    }
}


/* ----------------------------------------------------------------------------------
 *  CONNECTION HANDLING
 */

static void connection_loop(int sock)
{
    clamsmtp_thread_t* threads = NULL;
    int fd, i, x, r;

    /* Create the thread buffers */
    threads = (clamsmtp_thread_t*)calloc(g_state.max_threads, sizeof(clamsmtp_thread_t));
    if(!threads)
        errx(1, "out of memory");

    /* Now loop and accept the connections */
    while(!g_state.quit)
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
                g_state.quit = 1;
                break;
            };

            if(g_state.quit)
                break;

            continue;
        }

        /* Set timeouts on client */
        if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &g_state.timeout, sizeof(g_state.timeout)) < 0 ||
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &g_state.timeout, sizeof(g_state.timeout)) < 0)
            message(NULL, LOG_WARNING, "couldn't set timeouts on incoming connection");

        /* Look for thread and also clean up others */
        for(i = 0; i < g_state.max_threads; i++)
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
#ifdef _DEBUG
                else
                {
                    /* For debugging connection problems: */
                    messagex(NULL, LOG_DEBUG, "active connection thread: %x", (int)threads[i].tid);
                }
#endif
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
                    g_state.quit = 1;
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
            messagex(NULL, LOG_ERR, "too many connections open (max %d). sent 554 response", g_state.max_threads);

            write(fd, SMTP_STARTBUSY, KL(SMTP_STARTBUSY));
            shutdown(fd, SHUT_RDWR);
            close(fd);
            fd = -1;
        }
    }

    messagex(NULL, LOG_DEBUG, "waiting for threads to quit");

    /* Quit all threads here */
    for(i = 0; i < g_state.max_threads; i++)
    {
        /* Clean up quit threads */
        if(threads[i].tid != 0)
        {
            if(threads[i].fd != -1)
            {
                plock();
                    fd = threads[i].fd;
                    threads[i].fd = -1;
                punlock();

                shutdown(fd, SHUT_RDWR);
                close(fd);
            }

            pthread_join(threads[i].tid, NULL);
        }
    }
}

static void* thread_main(void* arg)
{
    clamsmtp_thread_t* thread = (clamsmtp_thread_t*)arg;
    struct sockaddr_any addr;
    struct sockaddr_any* outaddr;
    const char* outname;
    char buf[MAXPATHLEN];
    clamsmtp_context_t* ctx = NULL;
    int processing = 0;
    int ret = 0;
    int fd;

    ASSERT(thread);

    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    plock();
        /* Get the client socket */
        fd = thread->fd;
    punlock();

    ctx = (clamsmtp_context_t*)calloc(1, sizeof(clamsmtp_context_t));
    if(!ctx)
    {
        /* Special case. We don't have a context so clean up descriptor */
        close(fd);

        messagex(NULL, LOG_CRIT, "out of memory");
        RETURN(-1);
    }

    memset(ctx, 0, sizeof(*ctx));

    clio_init(&(ctx->server), "SERVER");
    clio_init(&(ctx->client), "CLIENT");
    clio_init(&(ctx->clam),   "CLAM  ");

    plock();
        /* Assign a unique id to the connection */
        ctx->id = g_unique_id++;

        /* We don't care about wraps, but we don't want zero */
        if(g_unique_id == 0)
            g_unique_id++;
    punlock();

    ctx->client.fd = fd;
    ASSERT(ctx->client.fd != -1);
    messagex(ctx, LOG_DEBUG, "processing %d on thread %x", ctx->client.fd, (int)pthread_self());

    memset(&addr, 0, sizeof(addr));
    SANY_LEN(addr) = sizeof(addr);

    /* Get the peer name */
    if(getpeername(ctx->client.fd, &SANY_ADDR(addr), &SANY_LEN(addr)) == -1 ||
       sock_any_ntop(&addr, buf, MAXPATHLEN, SANY_OPT_NOPORT) == -1)
        message(ctx, LOG_WARNING, "couldn't get peer address");
    else
        messagex(ctx, LOG_INFO, "accepted connection from: %s", buf);


    /* Create the server connection address */
    outaddr = &(g_state.outaddr);
    outname = g_state.outname;

    if(SANY_TYPE(*outaddr) == AF_INET &&
       outaddr->s.in.sin_addr.s_addr == 0)
    {
        /* Use the incoming IP as the default */
        in_addr_t in = addr.s.in.sin_addr.s_addr;
        memcpy(&addr, &(g_state.outaddr), sizeof(addr));
        addr.s.in.sin_addr.s_addr = in;

        outaddr = &addr;

        if(sock_any_ntop(outaddr, buf, MAXPATHLEN, 0) != -1)
            outname = buf;
    }


    /* Connect to the server */
    if(clio_connect(ctx, &(ctx->server), outaddr, outname) == -1)
        RETURN(-1);

    /* ... and to the AV daemon */
    if(connect_clam(ctx) == -1)
        RETURN(-1);


    /* call the processor */
    processing = 1;
    ret = smtp_passthru(ctx);

cleanup:

    if(ctx)
    {
        disconnect_clam(ctx);

        /* Let the client know about fatal errors */
        if(!processing && ret == -1 && clio_valid(&(ctx->client)))
           clio_write_data(ctx, &(ctx->client), SMTP_STARTFAILED);

        clio_disconnect(ctx, &(ctx->client));
        clio_disconnect(ctx, &(ctx->server));
    }

    /* mark this as done */
    plock();
        thread->fd = -1;
    punlock();

    return (void*)(ret == 0 ? 0 : 1);
}


/* ----------------------------------------------------------------------------------
 *  SMTP HANDLING
 */

static int smtp_passthru(clamsmtp_context_t* ctx)
{
    clio_t* io = NULL;
    char logline[LINE_LENGTH];
    int r, ret = 0;
    int neterror = 0;

    int first_rsp = 1;      /* The first 220 response from server to be filtered */
    int filter_ehlo = 0;    /* Filtering parts of an EHLO extensions response */
    int filter_host = 0;    /* Next response is 250 hostname, which we change */

    ASSERT(clio_valid(&(ctx->clam)) &&
           clio_valid(&(ctx->clam)));
    logline[0] = 0;

    for(;;)
    {
        if(clio_select(ctx, &io) == -1)
        {
            neterror = 1;
            RETURN(-1);
		}

        /* Client has data available, read a line and process */
        if(io == &(ctx->client))
        {
            if(clio_read_line(ctx, &(ctx->client), CLIO_DISCARD) == -1)
                RETURN(-1);

            /* Client disconnected, we're done */
            if(ctx->linelen == 0)
                RETURN(0);

            /* We don't let clients send really long lines */
            if(LINE_TOO_LONG(ctx))
            {
                if(clio_write_data(ctx, &(ctx->client), SMTP_TOOLONG) == -1)
                    RETURN(-1);

                continue;
            }

            /* Only valid after EHLO or HELO commands */
            filter_ehlo = 0;
            filter_host = 0;

            /* Handle the DATA section via our AV checker */
            if(is_first_word(ctx->line, DATA_CMD, KL(DATA_CMD)))
            {
                /* Send back the intermediate response to the client */
                if(clio_write_data(ctx, &(ctx->client), SMTP_DATAINTERMED) == -1)
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
             * We filter out features that we can't support in
             * the EHLO response (ESMTP). See below
             */
            else if(is_first_word(ctx->line, EHLO_CMD, KL(EHLO_CMD)))
            {
                messagex(ctx, LOG_DEBUG, "filtering EHLO response");
                filter_ehlo = 1;
                filter_host = 1;

                /* A new message */
                logline[0] = 0;
            }

            /*
             * We need our response to HELO to be modified in order
             * to prevent complaints about mail loops
             */
            else if(is_first_word(ctx->line, HELO_CMD, KL(HELO_CMD)))
            {
                filter_host = 1;

                /* A new message line */
                logline[0] = 0;
            }

            /*
             * We don't like these commands. Filter them out. We should have
             * filtered out their service extensions earlier in the EHLO response.
             * This is just for errant clients.
             */
            else if(is_first_word(ctx->line, STARTTLS_CMD, KL(STARTTLS_CMD)) ||
                    is_first_word(ctx->line, BDAT_CMD, KL(BDAT_CMD)))
            {
                messagex(ctx, LOG_DEBUG, "ESMTP feature not supported");

                if(clio_write_data(ctx, &(ctx->client), SMTP_NOTSUPP) == -1)
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
            if(clio_write_data(ctx, &(ctx->server), ctx->line) == -1)
                RETURN(-1);

            continue;
        }

        /* Server has data available, read a line and forward */
        if(io == &(ctx->server))
        {
            if(clio_read_line(ctx, &(ctx->server), CLIO_DISCARD) == -1)
                RETURN(-1);

            if(ctx->linelen == 0)
                RETURN(0);

            if(LINE_TOO_LONG(ctx))
                messagex(ctx, LOG_WARNING, "SMTP response line too long. discarded extra");

            /*
             * We intercept the first response we get from the server.
             * This allows us to change header so that it doesn't look
             * to the client server that we're in a wierd loop.
             *
             * In different situations using the local hostname or
             * 'localhost' don't work because the receiving mail server
             * expects one of those to be its own name. We use 'clamsmtp'
             * instead. No properly configured server would have this
             * as their domain name, and RFC 2821 allows us to use
             * an arbitrary but identifying string.
             */
            if(first_rsp)
            {
                first_rsp = 0;

                if(is_first_word(ctx->line, START_RSP, KL(START_RSP)))
                {
                    messagex(ctx, LOG_DEBUG, "intercepting initial response");

                    if(clio_write_data(ctx, &(ctx->client), SMTP_BANNER) == -1)
                        RETURN(-1);

                    /* Command handled */
                    continue;
                }
            }

            /*
             * Certain mail servers (Postfix 1.x in particular) do a loop check
             * on the 250 response after a EHLO or HELO. This is where we
             * filter that to prevent loopback errors.
             */
            if(filter_host)
            {
                filter_host = 0;

                /* Check for a simple '250 xxxx' */
                if(is_first_word(ctx->line, OK_RSP, KL(OK_RSP)))
                {
                    messagex(ctx, LOG_DEBUG, "intercepting host response");

                    if(clio_write_data(ctx, &(ctx->client), SMTP_HELO_RSP) == -1)
                        RETURN(-1);

                    continue;
                }

                /* Check for the continued response '250-xxxx' */
                if(check_first_word(ctx->line, OK_RSP, KL(OK_RSP), SMTP_MULTI_DELIMS) > 0)
                {
                    messagex(ctx, LOG_DEBUG, "intercepting host response");

                    if(clio_write_data(ctx, &(ctx->client), SMTP_EHLO_RSP) == -1)
                        RETURN(-1);

                    continue;
                }
            }

            /*
             * Filter out any EHLO responses that we can't or don't want
             * to support. For example pipelining or TLS.
             */
            if(filter_ehlo)
            {
                if((r = check_first_word(ctx->line, OK_RSP, KL(OK_RSP), SMTP_MULTI_DELIMS)) > 0)
                {
                    char* p = ctx->line + r;
                    if(is_first_word(p, ESMTP_PIPELINE, KL(ESMTP_PIPELINE)) ||
                       is_first_word(p, ESMTP_TLS, KL(ESMTP_TLS)) ||
                       is_first_word(p, ESMTP_CHUNK, KL(ESMTP_CHUNK)) ||
                       is_first_word(p, ESMTP_BINARY, KL(ESMTP_BINARY)) ||
                       is_first_word(p, ESMTP_CHECK, KL(ESMTP_CHECK)))
                    {
                        messagex(ctx, LOG_DEBUG, "filtered ESMTP feature: %s", trim_space(p));
                        continue;
                    }
                }
            }

            if(clio_write_data(ctx, &(ctx->client), ctx->line) == -1)
                RETURN(-1);

            continue;
        }
    }

cleanup:

    if(!neterror && ret == -1 && clio_valid(&(ctx->client)))
       clio_write_data(ctx, &(ctx->client), SMTP_FAILED);

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
    line = trim_start(line);

    strlcat(logline, line, l);

    /* Skip later white space */
    trim_end(logline);
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

    strlcpy(buf, g_state.directory, MAXPATHLEN);
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
        if(clio_write_data(ctx, &(ctx->client), SMTP_FAILED))
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
        if(clio_write_data(ctx, &(ctx->client),
                           g_state.bounce ? SMTP_DATAVIRUS : SMTP_DATAVIRUSOK) == -1)
            RETURN(-1);

        /* Any special post operation actions on the virus */
        quarantine_virus(ctx, buf);
        break;

    default:
        ASSERT(0 && "Invalid clam_scan_file return value");
        break;
    };

cleanup:
    if(havefile && !g_state.debug_files)
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
    if(clio_write_data(ctx, &(ctx->server), SMTP_DATA) == -1)
        return -1;

    if(read_server_response(ctx) == -1)
        return -1;

    /* If server returns an error then tell the client */
    if(!is_first_word(ctx->line, DATA_RSP, KL(DATA_RSP)))
    {
        if(clio_write_data(ctx, &(ctx->client), ctx->line) == -1)
            return -1;

        messagex(ctx, LOG_DEBUG, "server refused data transfer");

        return 0;
    }

    /* Now pull up the file and send it to the server */
    if(transfer_from_file(ctx, tempname) == -1)
    {
        /* Tell the client it went wrong */
        clio_write_data(ctx, &(ctx->client), SMTP_FAILED);
        return -1;
    }

    /* Okay read the response from the server and echo it to the client */
    if(read_server_response(ctx) == -1)
        return -1;

    if(clio_write_data(ctx, &(ctx->client), ctx->line) == -1)
        return -1;

    return 0;
}

static int read_server_response(clamsmtp_context_t* ctx)
{
    /* Read response line from the server */
    if(clio_read_line(ctx, &(ctx->server), CLIO_DISCARD) == -1)
        return -1;

    if(ctx->linelen == 0)
    {
        messagex(ctx, LOG_ERR, "server disconnected unexpectedly");

        /* Tell the client it went wrong */
        clio_write_data(ctx, &(ctx->client), SMTP_FAILED);
        return 0;
    }

    if(LINE_TOO_LONG(ctx))
        messagex(ctx, LOG_WARNING, "SMTP response line too long. discarded extra");

    return 0;
}


/* ----------------------------------------------------------------------------------
 *  CLAM AV
 */

static int connect_clam(clamsmtp_context_t* ctx)
{
    int ret = 0;

    ASSERT(ctx);
    ASSERT(!clio_valid(&(ctx->clam)));

    if(clio_connect(ctx, &(ctx->clam), &g_state.clamaddr, g_state.clamname) == -1)
       RETURN(-1);

    read_junk(ctx, ctx->clam.fd);

    /* Send a session and a check header to ClamAV */

    if(clio_write_data(ctx, &(ctx->clam), "SESSION\n") == -1)
        RETURN(-1);

    read_junk(ctx, ctx->clam.fd);
/*
    if(clio_write_data(ctx, &(ctx->clam), "PING\n") == -1 ||
       clio_read_line(ctx, &(ctx->clam), CLIO_DISCARD | CLIO_TRIM) == -1)
        RETURN(-1);

    if(strcmp(ctx->line, CONNECT_RESPONSE) != 0)
    {
        message(ctx, LOG_ERR, "clamd sent an unexpected response: %s", ctx->line);
        RETURN(-1);
    }
*/

cleanup:

    if(ret < 0)
        clio_disconnect(ctx, &(ctx->clam));

    return ret;
}

static int disconnect_clam(clamsmtp_context_t* ctx)
{
    if(!clio_valid(&(ctx->clam)))
        return 0;

    if(clio_write_data(ctx, &(ctx->clam), CLAM_DISCONNECT) != -1)
        read_junk(ctx, ctx->clam.fd);

    clio_disconnect(ctx, &(ctx->clam));
    return 0;
}

static int clam_scan_file(clamsmtp_context_t* ctx, const char* tempname, char* logline)
{
    int len;

    ASSERT(LINE_LENGTH > MAXPATHLEN + 32);

    strcpy(ctx->line, CLAM_SCAN);
    strcat(ctx->line, tempname);
    strcat(ctx->line, "\n");

    if(clio_write_data(ctx, &(ctx->clam), ctx->line) == -1)
        return -1;

    len = clio_read_line(ctx, &(ctx->clam), CLIO_DISCARD | CLIO_TRIM);
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
        add_to_logline(logline, "status=", "CLAMAV-ERROR");
        return -1;
    }

    messagex(ctx, LOG_ERR, "unexepected response from clamd: %s", ctx->line);
    return -1;
}


/* ----------------------------------------------------------------------------------
 *  TEMP FILE HANDLING
 */

static int quarantine_virus(clamsmtp_context_t* ctx, char* tempname)
{
    char buf[MAXPATHLEN];
    char* t;

    if(!g_state.quarantine)
        return 0;

    strlcpy(buf, g_state.directory, MAXPATHLEN);
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
    FILE* tfile = NULL;
    int tfd = -1;
    int ended_crlf = 1;     /* If the last line ended with a CRLF */
    int ret = 0;
    int count = 0;

    if((tfd = mkstemp(tempname)) == -1 ||
       (tfile = fdopen(tfd, "w")) == NULL)
    {
        message(ctx, LOG_ERR, "couldn't open temp file");
        RETURN(-1);
    }

    messagex(ctx, LOG_DEBUG, "created temporary file: %s", tempname);

    for(;;)
    {
        switch(clio_read_line(ctx, &(ctx->client), CLIO_QUIET))
        {
        case 0:
            messagex(ctx, LOG_ERR, "unexpected end of data from client");
            RETURN(-1);

        case -1:
            /* Message already printed */
            RETURN(-1);
        };

        if(ended_crlf && strcmp(ctx->line, DATA_END_SIG) == 0)
            break;

        /* We check errors on this later */
        fwrite(ctx->line, 1, ctx->linelen, tfile);
        count += ctx->linelen;

        /* Check if this line ended with a CRLF */
        ended_crlf = (strcmp(CRLF, ctx->line + (ctx->linelen - KL(CRLF))) == 0);
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

        if(ret <= 0)
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
    int header = 0;
    int ret = 0;

    file = fopen(filename, "r");
    if(file == NULL)
    {
        message(ctx, LOG_ERR, "couldn't open temporary file: %s", filename);
        RETURN(-1);
    }

    messagex(ctx, LOG_DEBUG, "sending from temporary file: %s", filename);

    while(fgets(ctx->line, LINE_LENGTH, file) != NULL)
    {
        if(g_state.header && !header)
        {
            /*
             * The first blank line we see means the headers are done.
             * At this point we add in our virus checked header.
             */
            if(is_blank_line(ctx->line))
            {
                if(clio_write_data_raw(ctx, &(ctx->server), (char*)g_state.header, strlen(g_state.header)) == -1 ||
                   clio_write_data_raw(ctx, &(ctx->server), CRLF, KL(CRLF)) == -1)
                    RETURN(-1);

                header = 1;
            }
        }

        if(clio_write_data_raw(ctx, &(ctx->server), ctx->line, strlen(ctx->line)) == -1)
            RETURN(-1);
    }

    if(ferror(file))
    {
        message(ctx, LOG_ERR, "error reading temporary file: %s", filename);
        RETURN(-1);
    }

    if(clio_write_data(ctx, &(ctx->server), DATA_END_SIG) == -1)
        RETURN(-1);

    messagex(ctx, LOG_DEBUG, "sent email data");

cleanup:

    if(file != NULL)
        fclose(file);

    return ret;
}


/* ----------------------------------------------------------------------------------
 *  NETWORKING
 */

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
        t = trim_start(buf);

        if(!said && *t)
        {
            messagex(ctx, LOG_DEBUG, "received junk data from daemon");
            said = 1;
        }
    }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
}
