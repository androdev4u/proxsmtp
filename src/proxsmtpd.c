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

#include <paths.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
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
    /* TODO: Timeout for above command */
    const char* directory;          /* The directory for temp files */
    int quarantine;                 /* Leave failed files in temp dir */
    int debug_files;                /* Leave all files in temp dir */
}
pxstate_t;

/* -----------------------------------------------------------------------
 *  STRINGS
 */

#define CRLF                "\r\n"

XXXXXXXXXXXXXXXXXxx
#define SMTP_DATAVIRUSOK    "250 Virus Detected; Discarded Email" CRLF
#define SMTP_DATAVIRUS      "550 Virus Detected; Content Rejected" CRLF

#define DEFAULT_CONFIG      CONF_PREFIX "/proxsmtpd.conf"

#define CFG_FILTER      "FilterCommand"
#define CFG_DIRECTORY   "TempDirectory"
#define CFG_QUARANTINE  "Quarantine"
#define CFG_DEBUGFILES  "DebugFiles"

/* -----------------------------------------------------------------------
 *  GLOBALS
 */

clstate_t g_clstate;

/* -----------------------------------------------------------------------
 *  FORWARD DECLARATIONS
 */

static void usage();
static int connect_clam(clctx_t* ctx);
static int disconnect_clam(clctx_t* ctx);
static int quarantine_virus(clctx_t* ctx);
static int transfer_to_cache(clctx_t* ctx);
static int clam_scan_file(clctx_t* ctx);

/* -----------------------------------------------------------------------
 *  SIMPLE MACROS
 */

/* ----------------------------------------------------------------------------------
 *  STARTUP ETC...
 */

int main(int argc, char* argv[])
{
    const char* configfile = DEFAULT_CONFIG;
    const char* pidfile = NULL;
    int dbg_level = -1;
    int warnargs = 0;
    int ch = 0;
    int r;
    char* t;

    /* Setup some defaults */
    memset(&g_clstate, 0, sizeof(g_clstate));
    g_clstate.header = DEFAULT_HEADER;
    g_clstate.directory = _PATH_TMP;

    /* We need the default to parse into a useable form, so we do this: */
    r = cb_parse_option(CFG_CLAMADDR, DEFAULT_CLAMAV);
    ASSERT(r == 1);

    sp_init("clamsmtpd");

    /*
     * We still accept our old arguments for compatibility reasons.
     * We fill them into the spstate structure directly
     */

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "bc:d:D:f:h:l:m:p:qt:v")) != -1)
    {
        switch(ch)
        {
        /* COMPAT: Actively reject messages */
        case 'b':
            if((r = cb_parse_option(CFG_BOUNCE, "on")) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
            break;

        /* COMPAT: Change the CLAM socket */
        case 'c':
            if((r = cb_parse_option(CFG_CLAMADDR, "on")) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
            break;

		/*  Don't daemonize  */
        case 'd':
            dbg_level = strtol(optarg, &t, 10);
            if(*t) /* parse error */
                errx(1, "invalid debug log level");
            dbg_level += LOG_ERR;
            break;

        /* COMPAT: The directory for the files */
        case 'D':
            if((r = sp_parse_option(CFG_DIRECTORY, optarg)) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
            break;

        /* The configuration file */
        case 'f':
            configfile = optarg;
            break;

        /* COMPAT: The header to add */
        case 'h':
            if((r = cb_parse_option(CFG_HEADER, optarg)) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
            break;

        /* COMPAT: Change our listening port */
        case 'l':
            if((r = sp_parse_option("Listen", optarg)) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
            break;

        /* COMPAT: The maximum number of threads */
        case 'm':
            if((r = sp_parse_option("MaxConnections", optarg)) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
            break;

        /* Write out a pid file */
        case 'p':
            pidfile = optarg;
            break;

        /* COMPAT: The timeout */
		case 't':
            if((r = sp_parse_option("TimeOut", optarg)) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
			break;

        /* COMPAT: Leave virus files in directory */
        case 'q':
            if((r = cb_parse_option(CFG_QUARANTINE, "on")) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
            break;

        /* Print version number */
        case 'v':
            printf("clamsmtpd (version %s)\n", VERSION);
            printf("          (config: %s)\n", DEFAULT_CONFIG);
            exit(0);
            break;

        /* COMPAT: Leave all files in the tmp directory */
        case 'X':
            if((r = cb_parse_option(CFG_DEBUGFILES, "on")) < 0)
                usage();
            ASSERT(r == 1);
            warnargs = 1;
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

    if(argc > 1)
        usage();
    if(argc == 1)
    {
        /* COMPAT: The out address */
        if((r = sp_parse_option("OutAddress", argv[0])) < 0)
            usage();
        ASSERT(r == 1);
        warnargs = 1;
    }

    if(warnargs)
        warnx("please use configuration file instead of command-line flags: %s", configfile);

    r = sp_run(configfile, pidfile, dbg_level);

    sp_done();

    return r;
}

static void usage()
{
    fprintf(stderr, "usage: clamsmtpd [-d debuglevel] [-f configfile] [-p pidfile]\n");
    fprintf(stderr, "       clamsmtpd -v\n");
    exit(2);
}

/* ----------------------------------------------------------------------------------
 *  SP CALLBACKS
 */

int cb_check_data(spctx_t* sp)
{
    int r = 0;
    clctx_t* ctx = (clctx_t*)sp;

    /* Connect to clamav */
    if(!spio_valid(&(ctx->clam)))
        r = connect_clam(ctx);

    /* transfer_to_cache */
    if(r != -1 && (r = transfer_to_cache(ctx)) > 0)

        /* ClamAV doesn't like empty files */
        r = clam_scan_file(ctx);

    switch(r)
    {

    /*
     * There was an error tell the client. We haven't notified
     * the server about any of this yet
     */
    case -1:
        if(sp_fail_data(sp, NULL) == -1)
            return -1;
        break;

    /*
     * No virus was found. Now we initiate a connection to the server
     * and transfer the file to it.
     */
    case 0:
        if(sp_done_data(sp, g_clstate.header) == -1)
            return -1;
        break;

    /*
     * A virus was found, normally we just drop the email. But if
     * requested we can send a simple message back to our client.
     * The server doesn't know data was ever sent, and the client can
     * choose to reset the connection to reuse it if it wants.
     */
    case 1:
        /* Any special post operation actions on the virus */
        quarantine_virus(ctx);

        if(sp_fail_data(sp, g_clstate.bounce ?
                            SMTP_DATAVIRUS : SMTP_DATAVIRUSOK) == -1)
            return -1;
        break;

    default:
        ASSERT(0 && "Invalid clam_scan_file return value");
        break;
    };

    return 0;
}

int cb_parse_option(const char* name, const char* value)
{
    if(strcasecmp(CFG_CLAMADDR, name) == 0)
    {
        if(sock_any_pton(value, &(g_clstate.clamaddr), SANY_OPT_DEFLOCAL) == -1)
            errx(2, "invalid " CFG_CLAMADDR " socket name: %s", value);
        g_clstate.clamname = value;
        return 1;
    }

    else if(strcasecmp(CFG_HEADER, name) == 0)
    {
        g_clstate.header = (const char*)trim_space((char*)value);

        if(strlen(g_clstate.header) == 0)
            g_clstate.header = NULL;

        return 1;
    }

    else if(strcasecmp(CFG_DIRECTORY, name) == 0)
    {
        g_clstate.directory = value;
        return 1;
    }

    else if(strcasecmp(CFG_BOUNCE, name) == 0)
    {
        if((g_clstate.bounce = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_BOUNCE);
        return 1;
    }

    else if(strcasecmp(CFG_QUARANTINE, name) == 0)
    {
        if((g_clstate.quarantine = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_BOUNCE);
        return 1;
    }

    else if(strcasecmp(CFG_DEBUGFILES, name) == 0)
    {
        if((g_clstate.debug_files = strtob(value)) == -1)
            errx(2, "invalid value for " CFG_DEBUGFILES);
        return 1;
    }

    return 0;
}

spctx_t* cb_new_context()
{
    clctx_t* ctx = (clctx_t*)calloc(1, sizeof(clctx_t));
    if(!ctx)
    {
        sp_messagex(NULL, LOG_CRIT, "out of memory");
        return NULL;
    }

    /* Initial preparation of the structure */
    spio_init(&(ctx->clam), "CLAMAV");
    return &(ctx->sp);
}

void cb_del_context(spctx_t* sp)
{
    clctx_t* ctx = (clctx_t*)sp;
    ASSERT(sp);

    disconnect_clam(ctx);
    free(ctx);
}

/* ----------------------------------------------------------------------------------
 *  CLAM AV
 */

static int connect_clam(clctx_t* ctx)
{
    int ret = 0;
    spctx_t* sp = &(ctx->sp);

    ASSERT(ctx);
    ASSERT(!spio_valid(&(ctx->clam)));

    if(spio_connect(sp, &(ctx->clam), &(g_clstate.clamaddr), g_clstate.clamname) == -1)
       RETURN(-1);

    spio_read_junk(sp, &(ctx->clam));

    /* Send a session and a check header to ClamAV */

    if(spio_write_data(sp, &(ctx->clam), "SESSION\n") == -1)
        RETURN(-1);

    spio_read_junk(sp, &(ctx->clam));

/*
    if(spio_write_data(sp, &(ctx->clam), "PING\n") == -1 ||
       spio_read_line(sp, &(ctx->clam), CLIO_DISCARD | CLIO_TRIM) == -1)
        RETURN(-1);

    if(strcmp(sp->line, CONNECT_RESPONSE) != 0)
    {
        sp_message(sp, LOG_ERR, "clamd sent an unexpected response: %s", ctx->line);
        RETURN(-1);
    }
*/

cleanup:

    if(ret < 0)
        spio_disconnect(sp, &(ctx->clam));

    return ret;
}

static int disconnect_clam(clctx_t* ctx)
{
    spctx_t* sp = &(ctx->sp);

    if(!spio_valid(&(ctx->clam)))
        return 0;

    if(spio_write_data(sp, &(ctx->clam), CLAM_DISCONNECT) != -1)
        spio_read_junk(sp, &(ctx->clam));

    spio_disconnect(sp, &(ctx->clam));
    return 0;
}

static int clam_scan_file(clctx_t* ctx)
{
    int len;
    spctx_t* sp = &(ctx->sp);

    /* Needs to be long enough to hold path names */
    ASSERT(SP_LINE_LENGTH > MAXPATHLEN + 32);

    strcpy(sp->line, CLAM_SCAN);
    strcat(sp->line, sp->cachename);
    strcat(sp->line, "\n");

    if(spio_write_data(sp, &(ctx->clam), sp->line) == -1)
        return -1;

    len = spio_read_line(sp, &(ctx->clam), SPIO_DISCARD | SPIO_TRIM);
    if(len == 0)
    {
        sp_messagex(sp, LOG_ERR, "clamd disconnected unexpectedly");
        return -1;
    }

    if(is_last_word(sp->line, CLAM_OK, KL(CLAM_OK)))
    {
        sp_add_log(sp, "status=", "CLEAN");
        sp_messagex(sp, LOG_DEBUG, "no virus");
        return 0;
    }

    if(is_last_word(sp->line, CLAM_FOUND, KL(CLAM_FOUND)))
    {
        len = strlen(sp->cachename);

        if(sp->linelen > len)
            sp_add_log(sp, "status=VIRUS:", sp->line + len + 1);
        else
            sp_add_log(sp, "status=", "VIRUS");

        sp_messagex(sp, LOG_DEBUG, "found virus");
        return 1;
    }

    if(is_last_word(sp->line, CLAM_ERROR, KL(CLAM_ERROR)))
    {
        sp_messagex(sp, LOG_ERR, "clamav error: %s", sp->line);
        sp_add_log(sp, "status=", "CLAMAV-ERROR");
        return -1;
    }

    sp_add_log(sp, "status=", "CLAMAV-ERROR");
    sp_messagex(sp, LOG_ERR, "unexepected response from clamd: %s", sp->line);
    return -1;
}

/* ----------------------------------------------------------------------------------
 *  TEMP FILE HANDLING
 */

static int quarantine_virus(clctx_t* ctx)
{
    char buf[MAXPATHLEN];
    spctx_t* sp = &(ctx->sp);
    char* t;

    if(!g_clstate.quarantine)
        return 0;

    strlcpy(buf, g_clstate.directory, MAXPATHLEN);
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
            sp_message(sp, LOG_ERR, "couldn't create quarantine file name");
            return -1;
        }

        /* Try to link the file over to the temp */
        if(link(sp->cachename, buf) == -1)
        {
            /* We don't want to allow race conditions */
            if(errno == EEXIST)
            {
                sp_message(sp, LOG_WARNING, "race condition when quarantining virus file: %s", buf);
                continue;
            }

            sp_message(sp, LOG_ERR, "couldn't quarantine virus file");
            return -1;
        }

        break;
    }

    sp_messagex(sp, LOG_INFO, "quarantined virus file as: %s", buf);
    return 0;
}

static int transfer_to_cache(clctx_t* ctx)
{
    spctx_t* sp = &(ctx->sp);
    int r, count = 0;
    const char* data;

    while((r = sp_read_data(sp, &data)) != 0)
    {
        if(r < 0)
            return -1;  /* Message already printed */

        count += r;

        if((r = sp_write_data(sp, data, r)) < 0)
            return -1;  /* Message already printed */
    }

    /* End the caching */
    if(sp_write_data(sp, NULL, 0) < 0)
        return -1;

    sp_messagex(sp, LOG_DEBUG, "wrote %d bytes to temp file", count);
    return count;
}


