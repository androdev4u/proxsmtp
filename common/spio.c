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

/*
 * select() and stdio are basically mutually exclusive.
 * Hence all of this code to try to get some buffering
 * along with select IO multiplexing.
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
#include <errno.h>

#include "usuals.h"
#include "sock_any.h"
#include "clamsmtpd.h"
#include "util.h"

#define MAX_LOG_LINE    79
#define GET_IO_NAME(io)  ((io)->name ? (io)->name : "???   ")

static void close_raw(int* fd)
{
    ASSERT(fd);
    shutdown(*fd, SHUT_RDWR);
    close(*fd);
    *fd = -1;
}

static void log_io_data(clamsmtp_context_t* ctx, clio_t* io, const char* data, int read)
{
    char buf[MAX_LOG_LINE + 1];
    int pos, len;

    ASSERT(ctx && io && data);

    for(;;)
    {
        data += strspn(data, "\r\n");

        if(!*data)
            break;

        pos = strcspn(data, "\r\n");

        len = pos < MAX_LOG_LINE ? pos : MAX_LOG_LINE;
        memcpy(buf, data, len);
        buf[len] = 0;

        messagex(0, LOG_DEBUG, "%s%s%s", GET_IO_NAME(io),
            read ? " < " : " > ", buf);

        data += pos;
    }
}

void clio_init(clio_t* io, const char* name)
{
    ASSERT(io && name);
    memset(io, 0, sizeof(*io));
    io->name = name;
    io->fd = -1;
}

int clio_connect(clamsmtp_context_t* ctx, clio_t* io, struct sockaddr_any* sany,
                 const char* addrname)
{
    int ret = 0;

    ASSERT(ctx && io && sany && addrname);
    ASSERT(io->fd == -1);

    if((io->fd = socket(SANY_TYPE(*sany), SOCK_STREAM, 0)) == -1)
        RETURN(-1);

    if(setsockopt(io->fd, SOL_SOCKET, SO_RCVTIMEO, &g_state.timeout, sizeof(g_state.timeout)) == -1 ||
       setsockopt(io->fd, SOL_SOCKET, SO_SNDTIMEO, &g_state.timeout, sizeof(g_state.timeout)) == -1)
        messagex(ctx, LOG_WARNING, "couldn't set timeouts on connection");

    if(connect(io->fd, &SANY_ADDR(*sany), SANY_LEN(*sany)) == -1)
        RETURN(-1);

cleanup:
    if(ret < 0)
    {
        if(io->fd != -1)
            close(io->fd);

        message(ctx, LOG_ERR, "couldn't connect to: %s", addrname);
        return -1;
    }

    ASSERT(io->fd != -1);
    messagex(ctx, LOG_DEBUG, "%s connected to: %s", GET_IO_NAME(io), addrname);
    return 0;
}

void clio_disconnect(clamsmtp_context_t* ctx, clio_t* io)
{
    ASSERT(ctx && io);

    if(clio_valid(io))
    {
        close_raw(&(io->fd));
        messagex(ctx, LOG_DEBUG, "%s connection closed", GET_IO_NAME(io));
    }
}

int clio_select(clamsmtp_context_t* ctx, clio_t** io)
{
    fd_set mask;

    ASSERT(ctx && io);
    FD_ZERO(&mask);
    *io = NULL;

    /* First check if buffers have any data */

    if(clio_valid(&(ctx->server)))
    {
        if(ctx->server.buflen > 0)
        {
            *io = &(ctx->server);
            return 0;
        }

        FD_SET(ctx->server.fd, &mask);
    }

    if(clio_valid(&(ctx->client)))
    {
        if(ctx->client.buflen > 0)
        {
            *io = &(ctx->client);
            return 0;
        }

        FD_SET(ctx->client.fd, &mask);
    }

    /* Select on the above */

    switch(select(FD_SETSIZE, &mask, NULL, NULL, &g_state.timeout))
    {
    case 0:
        messagex(ctx, LOG_ERR, "network operation timed out");
        return -1;
    case -1:
        message(ctx, LOG_ERR, "couldn't select on sockets");
        return -1;
    };

    /* See what came in */

    if(FD_ISSET(ctx->server.fd, &mask))
    {
        *io = &(ctx->server);
        return 0;
    }

    if(FD_ISSET(ctx->client.fd, &mask))
    {
        *io = &(ctx->client);
        return 0;
    }

    ASSERT(0 && "invalid result from select");
    return -1;
}

int clio_read_line(clamsmtp_context_t* ctx, clio_t* io, int opts)
{
    int l, x;
    char* t;
    unsigned char* p;

    ASSERT(ctx && io);

    if(!clio_valid(io))
    {
        messagex(ctx, LOG_WARNING, "tried to read from a closed connection");
        return 0;
    }

    ctx->line[0] = 0;
    t = ctx->line;
    l = LINE_LENGTH - 1;

    for(;;)
    {
        /* refil buffer if necessary */
        if(io->buflen == 0)
        {
            ASSERT(io->fd != -1);
            io->buflen = read(io->fd, io->buf, sizeof(char) * BUF_LEN);

            if(io->buflen == -1)
            {
                io->buflen = 0;

                if(errno == EINTR)
                {
                    /* When the application is quiting */
                    if(g_state.quit)
                        return -1;

                    /* For any other signal we go again */
                    continue;
                }

                if(errno == ECONNRESET) /* Not usually a big deal so supresse the error */
                    messagex(ctx, LOG_DEBUG, "connection disconnected by peer: %s", GET_IO_NAME(io));
                else if(errno == EAGAIN)
                    messagex(ctx, LOG_WARNING, "network read operation timed out: %s", GET_IO_NAME(io));
                else
                    message(ctx, LOG_ERR, "couldn't read data from socket: %s", GET_IO_NAME(io));

                /*
                 * The basic logic here is that if we've had a fatal error
                 * reading from the socket once then we shut it down as it's
                 * no good trying to read from again later.
                 */
                close_raw(&(io->fd));

                return -1;
            }
        }

        /* End of data */
        if(io->buflen == 0)
            break;

        /* Check for a new line */
        p = (unsigned char*)memchr(io->buf, '\n', io->buflen);

        if(p != NULL)
        {
            x = (p - io->buf) + 1;
            io->buflen -= x;
        }

        else
        {
            x = io->buflen;
            io->buflen = 0;
        }

        if(x > l)
           x = l;

        /* Copy from buffer line */
        memcpy(t, io->buf, x);
        t += x;
        l -= x;

        /* Move whatever we have in the buffer to the front */
        if(io->buflen > 0)
            memmove(io->buf, io->buf + x, io->buflen);

        /* Found a new line, done */
        if(p != NULL)
            break;

        /* If discarding then don't break when full */
        if(!(opts && CLIO_DISCARD) && l == 0)
            break;
    }

    ctx->linelen = (LINE_LENGTH - l) - 1;
    ASSERT(ctx->linelen < LINE_LENGTH);
    ctx->line[ctx->linelen] = 0;

    if(opts & CLIO_TRIM && ctx->linelen > 0)
    {
        t = ctx->line;

        while(*t && isspace(*t))
            t++;

        /* Bump the entire line down */
        l = t - ctx->line;
        memmove(ctx->line, t, (ctx->linelen + 1) - l);
        ctx->linelen -= l;

        /* Now the end */
        t = ctx->line + ctx->linelen;

        while(t > ctx->line && isspace(*(t - 1)))
        {
            *(--t) = 0;
            ctx->linelen--;
        }
    }

    if(!(opts & CLIO_QUIET))
        log_io_data(ctx, io, ctx->line, 1);

    return ctx->linelen;
}

int clio_write_data(clamsmtp_context_t* ctx, clio_t* io, const char* data)
{
    int len = strlen(data);
    ASSERT(ctx && io && data);

    if(!clio_valid(io))
    {
        message(ctx, LOG_ERR, "connection closed. can't write data.");
        return -1;
    }

    log_io_data(ctx, io, data, 0);
    return clio_write_data_raw(ctx, io, (unsigned char*)data, len);
}

int clio_write_data_raw(clamsmtp_context_t* ctx, clio_t* io, unsigned char* buf, int len)
{
    int r;

    ASSERT(ctx && io && buf);

    if(io->fd == -1)
        return 0;

    while(len > 0)
    {
        r = write(io->fd, buf, len);

        if(r > 0)
        {
            buf += r;
            len -= r;
        }

        else if(r == -1)
        {
            if(errno == EINTR)
            {
                /* When the application is quiting */
                if(g_state.quit)
                    return -1;

                /* For any other signal we go again */
                continue;
            }

            /*
             * The basic logic here is that if we've had a fatal error
             * writing to the socket once then we shut it down as it's
             * no good trying to write to it again later.
             */
            close_raw(&(io->fd));

            if(errno == EAGAIN)
                messagex(ctx, LOG_WARNING, "network write operation timed out: %s", GET_IO_NAME(io));
            else
                message(ctx, LOG_ERR, "couldn't write data to socket: %s", GET_IO_NAME(io));

            return -1;
        }
    }

    return 0;
}
