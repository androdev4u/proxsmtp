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
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <paths.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <err.h>

#include "usuals.h"

#include "compat.h"
#include "sock_any.h"
#include "stringx.h"
#include "smtppass.h"

/* -----------------------------------------------------------------------
 *  STRUCTURES
 */

typedef struct pxstate
{
    /* Settings ------------------------------- */
    const char* command;            /* The command to pipe email through */
    struct timeval timeout;         /* The command timeout */
    int pipe_cmd;                   /* Whether command is a pipe or not */
    const char* directory;          /* The directory for temp files */
}
pxstate_t;

/* -----------------------------------------------------------------------
 *  STRINGS
 */

#define SMTP_REJECTED       "550 Content Rejected\r\n"
#define DEFAULT_CONFIG      CONF_PREFIX "/proxsmtpd.conf"

#define CFG_FILTERCMD       "FilterCommand"
#define CFG_PIPECMD         "Pipe"
#define CFG_DIRECTORY       "TempDirectory"
#define CFG_DEBUGFILES      "DebugFiles"
#define CFG_CMDTIMEOUT      "CommandTimeout"

/* Poll time for waiting operations in milli seconds */
#define POLL_TIME           20

/* read & write ends of a pipe */
#define  READ_END   0
#define  WRITE_END  1

/* pre-set file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

/* -----------------------------------------------------------------------
 *  GLOBALS
 */

pxstate_t g_pxstate;

/* -----------------------------------------------------------------------
 *  FORWARD DECLARATIONS
 */

static void usage();
static int process_file_command(spctx_t* sp);
static int process_pipe_command(spctx_t* sp);
static void buffer_reject_message(char* data, char* buf, int buflen);
static int kill_process(spctx_t* sp, pid_t pid);
static int wait_process(spctx_t* sp, pid_t pid, int* status);

/* ----------------------------------------------------------------------------------
 *  STARTUP ETC...
 */

int main(int argc, char* argv[])
{
    const char* configfile = DEFAULT_CONFIG;
    const char* pidfile = NULL;
    int dbg_level = -1;
    int ch = 0;
    int r;
    char* t;

    /* Setup some defaults */
    memset(&g_pxstate, 0, sizeof(g_pxstate));
    g_pxstate.directory = _PATH_TMP;
    g_pxstate.pipe_cmd = 1;

    sp_init("proxsmtpd");

    /*
     * We still accept our old arguments for compatibility reasons.
     * We fill them into the spstate structure directly
     */

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "d:f:p:v")) != -1)
    {
        switch(ch)
        {
		/*  Don't daemonize  */
        case 'd':
            dbg_level = strtol(optarg, &t, 10);
            if(*t) /* parse error */
                errx(1, "invalid debug log level");
            dbg_level += LOG_ERR;
            break;

        /* The configuration file */
        case 'f':
            configfile = optarg;
            break;

        /* Write out a pid file */
        case 'p':
            pidfile = optarg;
            break;

        /* Print version number */
        case 'v':
            printf("clamsmtpd (version %s)\n", VERSION);
            printf("          (config: %s)\n", DEFAULT_CONFIG);
            exit(0);
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

    if(argc > 0)
        usage();

    r = sp_run(configfile, pidfile, dbg_level);

    sp_done();

    return r;
}

static void usage()
{
    fprintf(stderr, "usage: proxsmtpd [-d debuglevel] [-f configfile] [-p pidfile]\n");
    fprintf(stderr, "       proxsmtpd -v\n");
    exit(2);
}

/* ----------------------------------------------------------------------------------
 *  SP CALLBACKS
 */

int cb_check_data(spctx_t* ctx)
{
    int r = 0;

    if(!g_pxstate.command)
    {
        sp_messagex(ctx, LOG_WARNING, "no filter command specified. passing message through");

        if(sp_cache_data(ctx) == -1 ||
           sp_done_data(ctx, NULL) == -1)
            return -1;  /* Message already printed */
    }

    if(g_pxstate.pipe_cmd)
        r = process_pipe_command(ctx);
    else
        r = process_file_command(ctx);

    if(r == -1)
    {
        if(sp_fail_data(ctx, NULL) == -1)
            return -1;
    }

    return 0;
}

int cb_parse_option(const char* name, const char* value)
{
    char* t;

    if(strcasecmp(CFG_FILTERCMD, name) == 0)
    {
        g_pxstate.command = value;
        return 1;
    }

    else if(strcasecmp(CFG_DIRECTORY, name) == 0)
    {
        g_pxstate.directory = value;
        return 1;
    }

    else if(strcasecmp(CFG_CMDTIMEOUT, name) == 0)
    {
        g_pxstate.timeout.tv_sec = strtol(value, &t, 10);
        if(*t || g_pxstate.timeout.tv_sec <= 0)
            errx(2, "invalid setting: " CFG_CMDTIMEOUT);
        return 1;
    }

    else if(strcasecmp(CFG_PIPECMD, name) == 0)
    {
        if((g_pxstate.pipe_cmd = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_PIPECMD);
        return 1;
    }

    return 0;
}

spctx_t* cb_new_context()
{
    spctx_t* ctx = (spctx_t*)calloc(1, sizeof(spctx_t));
    if(!ctx)
        sp_messagex(NULL, LOG_CRIT, "out of memory");
    return ctx;
}

void cb_del_context(spctx_t* ctx)
{
    free(ctx);
}

/* -----------------------------------------------------------------------------
 * IMPLEMENTATION
 */

static int process_file_command(spctx_t* sp)
{
    pid_t pid;
    int ret = 0, status, r;

    /* For reading data from the process */
    int pipe_e[2];
    fd_set rmask;
    char obuf[1024];
    char ebuf[256];

    ASSERT(g_pxstate.command);

    memset(ebuf, 0, sizeof(ebuf));
    memset(pipe_e, ~0, sizeof(pipe_e));

    if(sp_cache_data(sp) == -1)
        RETURN(-1); /* message already printed */

    /* Create the pipe we need */
    if(pipe(pipe_e) == -1)
    {
        sp_message(sp, LOG_ERR, "couldn't create pipe for filter command");
        RETURN(-1);
    }

    /* Now fork the pipes across processes */
    switch(pid = fork())
    {
    case -1:
        sp_message(sp, LOG_ERR, "couldn't fork for filter command");
        RETURN(-1);

    /* The child process */
    case 0:

        /* Fixup our ends of the pipe */
        if(dup2(pipe_e[WRITE_END], STDERR) == -1)
        {
            sp_message(sp, LOG_ERR, "couldn't dup descriptor for filter command");
            exit(1);
        }

        /* Setup environment nicely */
        if(setenv("EMAIL", sp->cachename, 1) == -1 ||
           setenv("TMP", g_pxstate.directory, 1) == -1)
        {
            sp_messagex(sp, LOG_ERR, "couldn't setup environment for filter command");
            exit(1);
        }

        /* Now run the filter command */
        execl("/bin/sh", "sh", "-c", g_pxstate.command, NULL);

        /* If that returned then there was an error */
        sp_message(sp, LOG_ERR, "error executing the shell for filter command");
        exit(1);
        break;
    };

    /* The parent process */

    /* Close our copies of the pipes that we don't need */
    close(pipe_e[WRITE_END]);
    pipe_e[WRITE_END] = -1;

    /* Pipe shouldn't be blocking */
    fcntl(pipe_e[READ_END], F_SETFL, fcntl(pipe_e[READ_END], F_GETFL, 0) | O_NONBLOCK);

    /* Main read write loop */
    for(;;)
    {
        FD_SET(pipe_e[READ_END], &rmask);

        r = select(FD_SETSIZE, &rmask, NULL, NULL, &(g_pxstate.timeout));

        switch(r)
        {
        case -1:
            sp_message(sp, LOG_ERR, "couldn't select while listening to filter command");
            RETURN(-1);
        case 0:
            sp_messagex(sp, LOG_ERR, "timeout while listening to filter command");
            RETURN(-1);
        };

        for(;;)
        {
            /* Note because we handle as string we save one byte for null-termination */
            r = read(pipe_e[READ_END], obuf, sizeof(obuf) - 1);
            if(r < 0)
            {
                if(errno != EINTR || errno != EAGAIN)
                {
                    sp_message(sp, LOG_ERR, "couldn't read data from filter command");
                    RETURN(-1);
                }
            }

            else if(r == 0)
                break;

            /* Null terminate */
            obuf[r] = 0;

            /* And process */
            buffer_reject_message(obuf, ebuf, sizeof(ebuf));
        }

        /* Check if process is still around */
        if(waitpid(pid, &status, WNOHANG) == pid)
        {
            pid = 0;
            break;
        }
    }

    ASSERT(pid == 0);

    /* We only trust well behaved programs */
    if(!WIFEXITED(status))
    {
        sp_messagex(sp, LOG_ERR, "filter command terminated abnormally");
        RETURN(-1);
    }

    sp_messagex(sp, LOG_DEBUG, "filter exit code: %d", (int)WEXITSTATUS(status));

    /* A successful response */
    if(WEXITSTATUS(status) == 0)
    {
        if(sp_done_data(sp, NULL) == -1)
            RETURN(-1); /* message already printed */
    }

    /* Check code and use stderr if bad code */
    else
    {
        if(sp_fail_data(sp, ebuf[0] == 0 ? SMTP_REJECTED : ebuf) == -1)
            RETURN(-1); /* message already printed */
    }

    ret = 0;

cleanup:

    if(pipe_e[READ_END] != -1)
        close(pipe_e[READ_END]);
    if(pipe_e[WRITE_END] != -1)
        close(pipe_e[WRITE_END]);

    if(pid != 0)
        kill_process(sp, pid);

    return ret;
}

static int process_pipe_command(spctx_t* sp)
{
    pid_t pid;
    int ret = 0, status;
    int r, n, done;

    /* For sending data to the process */
    const char* ibuf = NULL;
    int ilen = 0;
    int pipe_i[2];
    fd_set wmask;
    int writing;

    /* For reading data from the process */
    int pipe_o[2];
    int pipe_e[2];
    fd_set rmask;
    int reading;
    char obuf[1024];
    char ebuf[256];

    ASSERT(g_pxstate.command);

    memset(ebuf, 0, sizeof(ebuf));

    memset(pipe_i, ~0, sizeof(pipe_i));
    memset(pipe_o, ~0, sizeof(pipe_o));
    memset(pipe_e, ~0, sizeof(pipe_e));

    /* Create the pipes we need */
    if(pipe(pipe_i) == -1 || pipe(pipe_o) == -1 || pipe(pipe_e) == -1)
    {
        sp_message(sp, LOG_ERR, "couldn't create pipes for filter command");
        RETURN(-1);
    }

    /* Now fork the pipes across processes */
    switch(pid = fork())
    {
    case -1:
        sp_message(sp, LOG_ERR, "couldn't fork for filter command");
        RETURN(-1);

    /* The child process */
    case 0:

        /* Fixup our ends of the pipe */
        if(dup2(pipe_i[READ_END], STDIN) == -1 ||
           dup2(pipe_o[WRITE_END], STDOUT) == -1 ||
           dup2(pipe_e[WRITE_END], STDERR) == -1)
        {
            sp_message(sp, LOG_ERR, "couldn't dup descriptors for filter command");
            exit(1);
        }

        /* Now run the filter command */
        execl("/bin/sh", "sh", "-c", g_pxstate.command, NULL);

        /* If that returned then there was an error */
        sp_message(sp, LOG_ERR, "error executing the shell for filter command");
        exit(1);
        break;
    };

    /* The parent process */

    /* Close our copies of the pipes that we don't need */
    close(pipe_i[READ_END]);
    pipe_i[READ_END] = -1;
    close(pipe_o[WRITE_END]);
    pipe_o[WRITE_END] = -1;
    close(pipe_e[WRITE_END]);
    pipe_e[WRITE_END] = -1;

    /* None of our pipes should be blocking */
    fcntl(pipe_i[WRITE_END], F_SETFL, fcntl(pipe_i[WRITE_END], F_GETFL, 0) | O_NONBLOCK);
    fcntl(pipe_o[READ_END], F_SETFL, fcntl(pipe_o[READ_END], F_GETFL, 0) | O_NONBLOCK);
    fcntl(pipe_e[READ_END], F_SETFL, fcntl(pipe_e[READ_END], F_GETFL, 0) | O_NONBLOCK);

    /* Main read write loop */
    for(;;)
    {
        reading = 0;
        writing = 0;
        done = 0;

        FD_ZERO(&rmask);
        FD_ZERO(&wmask);

        /* We only select on those that are still open */
        if(pipe_i[WRITE_END] != -1)
        {
            FD_SET(pipe_i[WRITE_END], &wmask);
            writing = 1;
        }
        if(pipe_o[READ_END] != -1)
        {
            FD_SET(pipe_o[READ_END], &rmask);
            reading = 1;
        }
        if(pipe_e[READ_END] != -1)
        {
            FD_SET(pipe_e[READ_END], &rmask);
            reading = 1;
        }

        /* If nothing open then go away */
        if(!reading && !writing)
            break;

        r = select(FD_SETSIZE, reading ? &rmask : NULL,
                    writing ? &wmask : NULL, NULL, &(g_pxstate.timeout));

        switch(r)
        {
        case -1:
            sp_message(sp, LOG_ERR, "couldn't select while listening to filter command");
            RETURN(-1);
        case 0:
            sp_messagex(sp, LOG_WARNING, "timeout while listening to filter command");
            RETURN(-1);
        };

        /* Handling of process's stdin */
        if(FD_ISSET(pipe_i[WRITE_END], &wmask))
        {
            if(ilen <= 0)
            {
                /* Read some more data into buffer */
                switch(r = sp_read_data(sp, &ibuf))
                {
                case -1:
                    RETURN(-1); /* Message already printed */
                case 0:
                    done = 1;
                    break;
                default:
                    ASSERT(r > 0);
                    ilen = r;
                    break;
                };
            }

            /* Write data from buffer */
            for(;;)
            {
                r = write(pipe_i[WRITE_END], ibuf, ilen);
                if(r == -1)
                {
                    if(errno == EAGAIN || errno == EINTR)
                        break;
                    else if(errno == EPIPE)
                    {
                        sp_message(sp, LOG_WARNING, "filter command closed input early");

                        /* Eat up the rest of the data */
                        while(sp_read_data(sp, &ibuf) > 0)
                            ;
                        done = 1;
                        break;
                    }

                    /* Otherwise it's a normal error */
                    sp_message(sp, LOG_ERR, "couldn't write to filter command");
                    RETURN(-1);
                }

                else
                {
                    ilen -= r;
                    ibuf += r;
                }

                break;
            }
        }

        /* Check if process is still around */
        if(!done && waitpid(pid, &status, WNOHANG) == pid)
        {
            pid = 0;
            done = 1;
        }

        /* Close output pipes if done */
        if(done)
        {
            close(pipe_i[WRITE_END]);
            pipe_i[WRITE_END] = -1;

            /* Force emptying of these guys */
            FD_SET(pipe_o[READ_END], &rmask);
            FD_SET(pipe_e[READ_END], &rmask);
        }

        /*
         * During normal operation we only read one block of data
         * at a time, but once done we make sure to drain the
         * output buffers dry.
         */
        do
        {
            /* Handling of stdout, which should be email data */
            if(FD_ISSET(pipe_o[READ_END], &rmask))
            {
                r = read(pipe_o[READ_END], obuf, sizeof(obuf));
                if(r > 0)
                {
                    if(sp_write_data(sp, obuf, r) == -1)
                        RETURN(-1); /* message already printed */
                }

                else if(r < 0)
                {
                    if(errno != EINTR || errno != EAGAIN)
                    {
                        sp_message(sp, LOG_ERR, "couldn't read data from filter command");
                        RETURN(-1);
                    }
                }
            }

            /* Handling of stderr, the last line of which we use as an err message*/
            if(FD_ISSET(pipe_e[READ_END], &rmask))
            {
                /* Note because we handle as string we save one byte for null-termination */
                n = read(pipe_e[READ_END], obuf, sizeof(obuf) - 1);
                if(n < 0)
                {
                    if(errno != EINTR || errno != EAGAIN)
                    {
                        sp_message(sp, LOG_ERR, "couldn't read data from filter command");
                        RETURN(-1);
                    }
                }

                else if(n > 0)
                {
                    /* Null terminate */
                    obuf[n] = 0;

                    /* And process */
                    buffer_reject_message(obuf, ebuf, sizeof(ebuf));
                }
            }

        }   /* when in 'done' mode we keep reading as long as there's data */
        while(done && !(r == 0 && n == 0));

        if(done)
            break;

        if(sp_is_quit())
            break;
    }

    /* exit the process if not completed */
    if(pid != 0)
    {
        if(wait_process(sp, pid, &status) == -1)
        {
            sp_messagex(sp, LOG_ERR, "timeout waiting for filter command to exit");
            RETURN(-1);
        }

        pid = 0;
    }

    /* We only trust well behaved programs */
    if(!WIFEXITED(status))
    {
        sp_messagex(sp, LOG_ERR, "filter command terminated abnormally");
        RETURN(-1);
    }

    sp_messagex(sp, LOG_DEBUG, "filter exit code: %d", (int)WEXITSTATUS(status));

    /* A successful response */
    if(WEXITSTATUS(status) == 0)
    {
        if(sp_done_data(sp, NULL) == -1)
            RETURN(-1); /* message already printed */
    }

    /* Check code and use stderr if bad code */
    else
    {
        if(sp_fail_data(sp, ebuf[0] == 0 ? SMTP_REJECTED : ebuf) == -1)
            RETURN(-1); /* message already printed */
    }

    ret = 0;

cleanup:

    if(pipe_i[READ_END] != -1)
        close(pipe_i[READ_END]);
    if(pipe_i[WRITE_END] != -1)
        close(pipe_i[WRITE_END]);
    if(pipe_o[READ_END] != -1)
        close(pipe_o[READ_END]);
    if(pipe_o[WRITE_END] != -1)
        close(pipe_o[WRITE_END]);
    if(pipe_e[READ_END] != -1)
        close(pipe_e[READ_END]);
    if(pipe_e[WRITE_END] != -1)
        close(pipe_e[WRITE_END]);

    if(pid != 0)
        kill_process(sp, pid);

    return ret;
}

static void buffer_reject_message(char* data, char* buf, int buflen)
{
    char* t;

    /* Take away all junk at beginning and end */
    data = trim_space(data);

    /*
     * Look for the last new line in the message. We
     * don't care about stuff before that.
     */
    t = strchr(data, '\n');
    if(t == NULL)
    {
        t = data;
    }
    else
    {
        t++;
        buf[0] = 0; /* Start a new message */
    }

    strlcat(buf, t, buflen);
}

static int wait_process(spctx_t* sp, pid_t pid, int* status)
{
    /* We poll x times a second */
    int waits = g_pxstate.timeout.tv_sec * (1000 / POLL_TIME);

    while(waits > 0)
    {
        switch(waitpid(pid, status, WNOHANG))
        {
        case 0:
            continue;
        case -1:
            sp_message(sp, LOG_CRIT, "error waiting on process");
            return -1;
        default:
            return 0;
        }

        usleep(POLL_TIME * 1000);
        waits--;
    }

    return -1;
}

static int kill_process(spctx_t* sp, pid_t pid)
{
    int status;

    if(kill(pid, SIGTERM) == -1)
    {
        if(errno == ESRCH)
            return 0;

        sp_message(sp, LOG_ERR, "couldn't send signal to process");
        return -1;
    }

    if(wait_process(sp, pid, &status) == -1)
    {
        if(kill(pid, SIGKILL) == -1)
        {
            if(errno == ESRCH)
                return 0;

            sp_message(sp, LOG_ERR, "couldn't send signal to process");
            return -1;
        }

        sp_messagex(sp, LOG_ERR, "process wouldn't quit. forced termination");
    }

   return 0;
}
