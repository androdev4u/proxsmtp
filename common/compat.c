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

#include "usuals.h"
#include "compat.h"

#ifndef HAVE_REALLOCF

void* reallocf(void* ptr, size_t size)
{
	void* ret = realloc(ptr, size);

	if(!ret && size)
		free(ptr);

	return ret;
}

#endif

#ifndef HAVE_STRLWR
char* strlwr(char* s)
{
    char* t = s;
    while(*t)
    {
        *t = tolower(*t);
        t++;
    }
    return s;
}
#endif

#ifndef HAVE_STRUPR
char* strupr(char* s)
{
    char* t = s;
    while(*t)
    {
        *t = toupper(*t);
        t++;
    }
    return s;
}
#endif

#ifndef HAVE_STRLCPY

#ifndef HAVE_STRNCPY
#error neither strncpy or strlcpy found
#endif

void strlcpy(char* dest, const char* src, size_t count)
{
        if(count > 0)
        {
                strncpy(dest, src, count);
                dest[count - 1] = 0;
        }
}
#endif

#ifndef HAVE_STRLCAT

#ifndef HAVE_STRNCAT
#error neither strncat or strlcat found
#endif

void strlcat(char* dest, const char* src, size_t count)
{
        if(count > 0)
        {
                strncat(dest, src, count);
                dest[count - 1] = 0;
        }
}
#endif


