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

#ifndef __CLAMSMTPD_H__
#define __CLAMSMTPD_H__

#include <sock_any.h>

/* IO Buffers see clio.c ---------------------------------------------------- */

#define BUF_LEN 256

typedef struct clio
{
    int fd;
    const char* name;
    unsigned char buf[BUF_LEN];
    size_t buflen;
}
clio_t;

/* The main context --------------------------------------------------------- */

/*
 * A generous maximum line length. It needs to be longer than
 * a full path on this system can be, because we pass the file
 * name to clamd.
 */

#if 2000 > MAXPATHLEN
    #define LINE_LENGTH 2000
#else
    #define LINE_LENGTH (MAXPATHLEN + 128)
#endif

typedef struct clamsmtp_context
{
    unsigned int id;        /* Identifier for the connection */

    clio_t client;          /* Connection to client */
    clio_t server;          /* Connection to server */
    clio_t clam;            /* Connection to clamd */

    char line[LINE_LENGTH]; /* Working buffer */
    int linelen;            /* Length of valid data in above */
}
clamsmtp_context_t;

#define LINE_TOO_LONG(ctx)      ((ctx)->linelen >= (LINE_LENGTH - 2))
#define RETURN(x)               { ret = x; goto cleanup; }


/* Implemented in clio.c ---------------------------------------------------- */

#define CLIO_TRIM           0x00000001
#define CLIO_DISCARD        0x00000002
#define CLIO_QUIET          0x00000004
#define clio_valid(io)      ((io)->fd != -1)

void clio_init(clio_t* io, const char* name);
int clio_connect(clamsmtp_context_t* ctx, clio_t* io, struct sockaddr_any* sany, const char* addrname);
void clio_disconnect(clamsmtp_context_t* ctx, clio_t* io);
int clio_select(clamsmtp_context_t* ctx, clio_t** io);
int clio_read_line(clamsmtp_context_t* ctx, clio_t* io, int trim);
int clio_write_data(clamsmtp_context_t* ctx, clio_t* io, const char* data);
int clio_write_data_raw(clamsmtp_context_t* ctx, clio_t* io, unsigned char* buf, int len);


/* Implemented in clstate.c ------------------------------------------------ */

typedef struct clstate
{
	/* Settings ------------------------------- */
	int debug_level;				/* The level to print stuff to console */
	int max_threads;				/* Maximum number of threads to process at once */
	struct timeval timeout;			/* Timeout for communication */

	struct sockaddr_any outaddr;	/* The outgoing address */
	const char* outname;
	struct sockaddr_any clamaddr;   /* Address for connecting to clamd */
	const char* clamname;
	struct sockaddr_any listenaddr; /* Address to listen on */
    const char* listenname;

	const char* header;	            /* The header to add to email */
	const char* directory;     		/* The directory for temp files */
	int bounce;                     /* Send back a reject line */
	int quarantine;                 /* Leave virus files in temp dir */
	int debug_files;                /* Leave all files in temp dir */
    int transparent;                /* Transparent proxying */

	/* State --------------------------------- */
	int daemonized; 			/* Whether process is daemonized or not */
	pthread_mutex_t mutex;    	/* The main mutex */
	int quit;					/* Quit the process */

	/* Internal Use ------------------------- */
	char* _p;
    pthread_mutexattr_t _mtxattr;
}
clstate_t;

extern clstate_t g_state;

void clstate_init(clstate_t* state);
int clstate_parse_config(clstate_t* state, const char* configfile);
void clstate_validate(clstate_t* state);
void clstate_cleanup(clstate_t* state);

#endif /* __CLAMSMTPD_H__ */
