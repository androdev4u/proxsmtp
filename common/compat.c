
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


