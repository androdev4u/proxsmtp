#ifndef __CLAMSMTPD_H__
#define __CLAMSMTPD_H__

/* A generous maximum line length. */
#define LINE_LENGTH 2000

typedef struct clamsmtp_context
{
    unsigned int id;        /* Identifier for the connection */

    int client;             /* Connection to client */
    int server;             /* Connection to server */
    int clam;               /* Connection to clamd */

    char line[LINE_LENGTH]; /* Working buffer */
    int linelen;            /* Length of valid data in above */
}
clamsmtp_context_t;

extern int g_daemonized;              /* Currently running as a daemon */
extern int g_debuglevel;              /* what gets logged to console */
extern pthread_mutex_t g_mutex;       /* The main mutex */

#endif /* __CLAMSMTPD_H__ */
