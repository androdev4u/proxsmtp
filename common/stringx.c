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
 *
 */

#include <sys/types.h>

#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <stdarg.h>
#include <strings.h>

#include "usuals.h"
#include "compat.h"
#include "clamsmtpd.h"
#include "util.h"

/* ----------------------------------------------------------------------------------
 *  Logging
 */

const char kMsgDelimiter[] = ": ";
#define MAX_MSGLEN  256

static void vmessage(clamsmtp_context_t* ctx, int level, int err,
                     const char* msg, va_list ap)
{
    size_t len;
    char* m;
    int e = errno;

    if(g_daemonized)
    {
        if(level >= LOG_DEBUG)
            return;
    }
    else
    {
        if(g_debuglevel < level)
            return;
    }

    ASSERT(msg);

    len = strlen(msg) + 20 + MAX_MSGLEN;
    m = (char*)alloca(len);

    if(m)
    {
        if(ctx)
            snprintf(m, len, "%06X: %s%s", ctx->id, msg, err ? ": " : "");
        else
            snprintf(m, len, "%s%s", msg, err ? ": " : "");

        if(err)
        {
            /* TODO: strerror_r doesn't want to work for us
            strerror_r(e, m + strlen(m), MAX_MSGLEN); */
            strncat(m, strerror(e), len);
        }

        m[len - 1] = 0;
        msg = m;
    }

    /* Either to syslog or stderr */
    if(g_daemonized)
        vsyslog(level, msg, ap);
    else
        vwarnx(msg, ap);
}

void messagex(clamsmtp_context_t* ctx, int level, const char* msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vmessage(ctx, level, 0, msg, ap);
    va_end(ap);
}

void message(clamsmtp_context_t* ctx, int level, const char* msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vmessage(ctx, level, 1, msg, ap);
    va_end(ap);
}

/* ----------------------------------------------------------------------------------
 *  Parsing
 */

int is_first_word(const char* line, const char* word, int len)
{
    ASSERT(line);
    ASSERT(word);
    ASSERT(len > 0);

    while(*line && isspace(*line))
        line++;

    if(strncasecmp(line, word, len) != 0)
        return 0;

    line += len;
    return !*line || isspace(*line);
}

int check_first_word(const char* line, const char* word, int len, char* delims)
{
    const char* t;
    int found = 0;

    ASSERT(line);
    ASSERT(word);
    ASSERT(len > 0);

    t = line;

    while(*t && strchr(delims, *t))
        t++;

    if(strncasecmp(t, word, len) != 0)
        return 0;

    t += len;

    while(*t && strchr(delims, *t))
    {
        found = 1;
        t++;
    }

    return (!*t || found) ? t - line : 0;
}

int is_last_word(const char* line, const char* word, int len)
{
    const char* t;

    ASSERT(line);
    ASSERT(word);
    ASSERT(len > 0);

    t = line + strlen(line);

    while(t > line && isspace(*(t - 1)))
        --t;

    if(t - len < line)
        return 0;

    return strncasecmp(t - len, word, len) == 0;
}

int is_blank_line(const char* line)
{
    /* Small optimization */
    if(!*line)
        return 1;

    while(*line && isspace(*line))
        line++;

    return *line == 0;
}

char* trim_start(const char* data)
{
    while(*data && isspace(*data))
        ++data;
    return (char*)data;
}

char* trim_end(char* data)
{
    char* t = data + strlen(data);

    while(t > data && isspace(*(t - 1)))
    {
        t--;
        *t = 0;
    }

    return data;
}

char* trim_space(char* data)
{
    data = (char*)trim_start(data);
    return trim_end(data);
}

/* -----------------------------------------------------------------------
 * Locking
 */

void plock()
{
    int r;

#ifdef _DEBUG
    int wait = 0;
#endif

#ifdef _DEBUG
    r = pthread_mutex_trylock(&g_mutex);
    if(r == EBUSY)
    {
        wait = 1;
        message(NULL, LOG_DEBUG, "thread will block: %d", pthread_self());
        r = pthread_mutex_lock(&g_mutex);
    }

#else
    r = pthread_mutex_lock(&g_mutex);

#endif

    if(r != 0)
    {
        errno = r;
        message(NULL, LOG_CRIT, "threading problem. couldn't lock mutex");
    }

#ifdef _DEBUG
    else if(wait)
    {
        message(NULL, LOG_DEBUG, "thread unblocked: %d", pthread_self());
    }
#endif
}

void punlock()
{
    int r = pthread_mutex_unlock(&g_mutex);
    if(r != 0)
    {
        errno = r;
        message(NULL, LOG_CRIT, "threading problem. couldn't unlock mutex");
    }
}

