
#ifndef __SOCK_ANY_H__
#define __SOCK_ANY_H__

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

struct sockaddr_any
{
  union _sockaddr_any
  {
    /* The header */
    struct sockaddr a;

    /* The different types */
    struct sockaddr_un un;
    struct sockaddr_in in;
#ifdef HAVE_INET6
    struct sockaddr_in6 in6;
#endif
  } s;
  size_t namelen;
};

#define SANY_ADDR(any)  ((any).s.a)
#define SANY_LEN(any)   ((any).namelen)
#define SANY_TYPE(any)  ((any).s.a.sa_family)

int sock_any_pton(const char* addr, struct sockaddr_any* any, int defport);
int sock_any_ntop(struct sockaddr_any* any, char* addr, size_t addrlen);

#endif /* __SOCK_ANY_H__ */
