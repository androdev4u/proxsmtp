

#ifndef __USUALS_H__
#define __USUALS_H__

#include <sys/types.h>

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "compat.h"

#ifndef NULL
#define NULL 0
#endif

#ifndef max
#define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)  (((a) < (b)) ? (a) : (b))
#endif

#define countof(x) (sizeof(x) / sizeof(x[0]))

#ifdef _DEBUG
  #include "assert.h"
  #define ASSERT assert
#else
  #define ASSERT
#endif

#endif /* __USUALS_H__ */
