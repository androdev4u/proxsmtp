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
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include "usuals.h"
#include "sock_any.h"
#include "stringx.h"
#include "sppriv.h"

#define MAX_LOG_LINE    79
#define GET_IO_NAME(io)  ((io)->name ? (io)->name : "???   ")

static void close_raw(int* fd)
{
    ASSERT(fd);
    shutdown(*fd, SHUT_RDWR);
    close(*fd);
    *fd = -1;
}

static void log_io_data(spctx_t* ctx, spio_t* io, const char* data, int read)
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

        sp_messagex(ctx, LOG_DEBUG, "%s%s%s", GET_IO_NAME(io),
            read ? " < " : " > ", buf);

        data += pos;
    }
}

void spio_init(spio_t* io, const char* name)
{
    ASSERT(io && name);
    memset(io, 0, sizeof(*io));
    io->name = name;
    io->fd = -1;
}

int spio_connect(spctx_t* ctx, spio_t* io, const struct sockaddr_any* sany,
                 const char* addrname)
{
    int ret = 0;

    ASSERT(ctx && io && sany && addrname);
    ASSERT(io->fd == -1);

    if((io->fd = socket(SANY_TYPE(*sany), SOCK_STREAM, 0)) == -1)
        RETURN(-1);

    if(setsockopt(io->fd, SOL_SOCKET, SO_RCVTIMEO, &(g_state.timeout), sizeof(g_state.timeout)) == -1 ||
       setsockopt(io->fd, SOL_SOCKET, SO_SNDTIMEO, &(g_state.timeout), sizeof(g_state.timeout)) == -1)
        sp_messagex(ctx, LOG_WARNING, "couldn't set timeouts on connection");

    if(connect(io->fd, &SANY_ADDR(*sany), SANY_LEN(*sany)) == -1)
        RETURN(-1);

cleanup:
    if(ret < 0)
    {
        if(io->fd != -1)
            close(io->fd);

        sp_message(ctx, LOG_ERR, "couldn't connect to: %s", addrname);
        return -1;
    }

    ASSERT(io->fd != -1);
    sp_messagex(ctx, LOG_DEBUG, "%s connected to: %s", GET_IO_NAME(io), addrname);
    return 0;
}

void spio_disconnect(spctx_t* ctx, spio_t* io)
{
    ASSERT(ctx && io);

    if(spio_valid(io))
    {
        close_raw(&(io->fd));
        sp_messagex(ctx, LOG_DEBUG, "%s connection closed", GET_IO_NAME(io));
    }
}

unsigned int spio_select(spctx_t* ctx, ...)
{
    fd_set mask;
    spio_t* io;
    int ret = 0;
    int i = 0;
    va_list ap;

    ASSERT(ctx);
    FD_ZERO(&mask);

    va_start(ap, ctx);

    while((io = va_arg(ap, spio_t*)) != NULL)
    {
        /* We can't handle more than 31 args */
        if(i > (sizeof(int) * 8) - 2)
            break;

        /* Check if the buffer has something in it */
        if(io->_ln > 0)
            ret |= (1 << i);

        /* Mark for select */
        FD_SET(io->fd, &mask);

        i++;
    }

    va_end(ap);

    /* If any buffers had something present, then return */
    if(ret != 0)
        return ret;

    /* Otherwise wait on more data */
    switch(select(FD_SETSIZE, &mask, NULL, NULL,
           (struct timeval*)&(g_state.timeout)))
    {
    case 0:
        sp_messagex(ctx, LOG_ERR, "network operation timed out");
        return ~0;
    case -1:
        sp_message(ctx, LOG_ERR, "couldn't select on sockets");
        return ~0;
    };

    /* See what came in */
    i = 0;

    va_start(ap, ctx);

    while((io = va_arg(ap, spio_t*)) != NULL)
    {
        /* We can't handle more than 31 args */
        if(i > (sizeof(int) * 8) - 2)
            break;

        /* Check if the buffer has something in it */
        if(FD_ISSET(io->fd, &mask))
            ret |= (1 << i);

        i++;
    }

    return ret;
}

int spio_read_line(spctx_t* ctx, spio_t* io, int opts)
{
    int l, x;
    char* t;
    unsigned char* p;

    ASSERT(ctx && io);

    if(!spio_valid(io))
    {
        sp_messagex(ctx, LOG_WARNING, "tried to read from a closed connection");
        return 0;
    }

    ctx->line[0] = 0;
    t = ctx->line;
    l = SP_LINE_LENGTH - 1;

    for(;;)
    {
        /* refil buffer if necessary */
        if(io->_ln == 0)
        {
            ASSERT(io->fd != -1);
            io->_ln = read(io->fd, io->_bf, sizeof(char) * SPIO_BUFLEN);

            if(io->_ln == -1)
            {
                io->_ln = 0;

                if(errno == EINTR)
                {
                    /* When the application is quiting */
                    if(sp_is_quit())
                        return -1;

                    /* For any other signal we go again */
                    continue;
                }

                if(errno == ECONNRESET) /* Not usually a big deal so supresse the error */
                    sp_messagex(ctx, LOG_DEBUG, "connection disconnected by peer: %s", GET_IO_NAME(io));
                else if(errno == EAGAIN)
                    sp_messagex(ctx, LOG_WARNING, "network read operation timed out: %s", GET_IO_NAME(io));
                else
                    sp_message(ctx, LOG_ERR, "couldn't read data from socket: %s", GET_IO_NAME(io));

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
        if(io->_ln == 0)
            break;

        /* Check for a new line */
        p = (unsigned char*)memchr(io->_bf, '\n', io->_ln);

        if(p != NULL)
        {
            x = (p - io->_bf) + 1;
            io->_ln -= x;
        }

        else
        {
            x = io->_ln;
            io->_ln = 0;
        }

        if(x > l)
           x = l;

        /* Copy from buffer line */
        memcpy(t, io->_bf, x);
        t += x;
        l -= x;

        /* Move whatever we have in the buffer to the front */
        if(io->_ln > 0)
            memmove(io->_bf, io->_bf + x, io->_ln);

        /* Found a new line, done */
        if(p != NULL)
            break;

        /* If discarding then don't break when full */
        if(!(opts && SPIO_DISCARD) && l == 0)
            break;
    }

    ctx->linelen = (SP_LINE_LENGTH - l) - 1;
    ASSERT(ctx->linelen < SP_LINE_LENGTH);
    ctx->line[ctx->linelen] = 0;

    if(opts & SPIO_TRIM && ctx->linelen > 0)
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

    if(!(opts & SPIO_QUIET))
        log_io_data(ctx, io, ctx->line, 1);

    return ctx->linelen;
}

int spio_write_data(spctx_t* ctx, spio_t* io, const char* data)
{
    int len = strlen(data);
    ASSERT(ctx && io && data);

    if(!spio_valid(io))
    {
        sp_message(ctx, LOG_ERR, "connection closed. can't write data.");
        return -1;
    }

    log_io_data(ctx, io, data, 0);
    return spio_write_data_raw(ctx, io, (unsigned char*)data, len);
}

int spio_write_data_raw(spctx_t* ctx, spio_t* io, unsigned char* buf, int len)
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
                if(sp_is_quit())
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
                sp_messagex(ctx, LOG_WARNING, "network write operation timed out: %s", GET_IO_NAME(io));
            else
                sp_message(ctx, LOG_ERR, "couldn't write data to socket: %s", GET_IO_NAME(io));

            return -1;
        }
    }

    return 0;
}

void spio_read_junk(spctx_t* ctx, spio_t* io)
{
    char buf[16];
    const char* t;
    int said = 0;
    int l;

    ASSERT(ctx);
    ASSERT(io);

    /* Truncate any data in buffer */
    io->_ln = 0;

    if(!spio_valid(io))
        return;

    /* Make it non blocking */
    fcntl(io->fd, F_SETFL, fcntl(io->fd, F_GETFL, 0) | O_NONBLOCK);

    for(;;)
    {
        l = read(io->fd, buf, sizeof(buf) - 1);
        if(l <= 0)
            break;

        buf[l] = 0;
        t = trim_start(buf);

        if(!said && *t)
        {
            sp_messagex(ctx, LOG_DEBUG, "received junk data from daemon");
            said = 1;
        }
    }

    fcntl(io->fd, F_SETFL, fcntl(io->fd, F_GETFL, 0) & ~O_NONBLOCK);
}
