

#ifndef _COMPAT_H_
#define _COMPAT_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#ifndef HAVE_STDARG_H
#error ERROR: Must have a working stdarg.h header
#else
#include <stdarg.h>
#endif

#ifndef HAVE_REALLOCF
void* reallocf(void* p, size_t sz);
#endif

#include <pthread.h>

/* TODO: Move this logic to configure */
#if HAVE_ERR_MUTEX == 1
# define MUTEX_TYPE PTHREAD_MUTEX_ERRORCHECK_NP
#else
# if HAVE_ERR_MUTEX == 2
#   define MUTEX_TYPE PTHREAD_MUTEX_ERRORCHECK
# else
#   error "Need error checking mutex functionality"
# endif
#endif

#ifndef HAVE_STRLWR
char* strlwr(char* s);
#endif

#ifndef HAVE_STRUPR
char* strupr(char* s);
#endif

#ifndef HAVE_STRLCAT
void strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCPY
void strlcpy(char *dst, const char *src, size_t size);
#endif

#endif /* _COMPAT_H_ */
