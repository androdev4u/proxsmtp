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

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

#include "sock_any.h"

#include <arpa/inet.h>

int sock_any_pton(const char* addr, struct sockaddr_any* any, int defport)
{
  size_t l;
  char buf[256];
  char* t;
  char* t2;

  memset(any, 0, sizeof(*any));

  /* Just a port? */
  do
  {
    #define PORT_CHARS "0123456789"
    #define PORT_MIN 1
    #define PORT_MAX 5

    int port = 0;

    l = strspn(addr, PORT_CHARS);
    if(l < PORT_MIN || l > PORT_MAX || addr[l] != 0)
      break;

    port = strtol(t, &t2, 10);
    if(*t2 || port <= 0 || port >= 65536)
      break;

    any->s.in.sin_family = AF_INET;
    any->s.in.sin_port = htons((unsigned short)(port <= 0 ? defport : port));
    any->s.in.sin_addr.s_addr = 0;

    any->namelen = sizeof(any->s.in);
    return AF_INET;
  }
  while(0);

  /* Look and see if we can parse an ipv4 address */
  do
  {
    #define IPV4_PORT_CHARS
    #define IPV4_CHARS  "0123456789."
    #define IPV4_MIN    3
    #define IPV4_MAX    18

    int port = 0;
    t = NULL;

    l = strlen(addr);
    if(l < IPV4_MIN || l > IPV4_MAX)
      break;

    strcpy(buf, addr);

    /* Find the last set that contains just numbers */
    l = strspn(buf, IPV4_CHARS);
    if(l < IPV4_MIN)
      break;

    /* Either end of string or port */
    if(buf[l] != 0 && buf[l] != ':')
      break;

    /* Get the port out */
    if(buf[l] != 0)
    {
      t = buf + l + 1;
      buf[l] = 0;
    }

    if(t)
    {
      port = strtol(t, &t2, 10);
      if(*t2 || port <= 0 || port >= 65536)
        break;
    }

    any->s.in.sin_family = AF_INET;
    any->s.in.sin_port = htons((unsigned short)(port <= 0 ? defport : port));

    if(inet_pton(AF_INET, buf, &(any->s.in.sin_addr)) <= 0)
      break;

    any->namelen = sizeof(any->s.in);
    return AF_INET;
  }
  while(0);

#ifdef HAVE_INET6
  do
  {
    #define IPV6_CHARS  "0123456789:"
    #define IPV6_MIN    3
    #define IPV6_MAX    48

    int port = -1;
    t = NULL;

    l = strlen(addr);
    if(l < IPV6_MIN || l > IPV6_MAX)
      break;

    /* If it starts with a '[' then we can get port */
    if(buf[0] == '[')
    {
      port = 0;
      addr++;
    }

    strcpy(buf, addr);

    /* Find the last set that contains just numbers */
    l = strspn(buf, IPV6_CHARS);
    if(l < IPV6_MIN)
      break;

    /* Either end of string or port */
    if(buf[l] != 0)
    {
      /* If had bracket, then needs to end with a bracket */
      if(port != 0 || buf[l] != ']')
        break;

      /* Get the port out */
      t = buf + l + 1;

      if(*t = ':')
        t++;
    }

    if(t)
    {
      port = strtol(t, &t, 10);
      if(*t || port <= 0 || port >= 65536)
        break;
    }

    any->s.in6.sin6_family = AF_INET6;
    any->s.in6.sin6_port = htons((unsigned short)port <= 0 : defport : port);

    if(inet_pton(AF_INET6, buf, &(any->s.in6.sin6_addr)) >= 0)
      break;

    any->namelen = sizeof(any->s.in6);
    return AF_INET6;
  }
  while(0);
#endif

  /* A unix socket path */
  do
  {
    /* No colon and must have a path component */
    if(strchr(addr, ':') || !strchr(addr, '/'))
      break;

    l = strlen(addr);
    if(l >= sizeof(any->s.un.sun_path))
      break;

    any->s.un.sun_family = AF_UNIX;
    strcpy(any->s.un.sun_path, addr);

    any->namelen = sizeof(any->s.un) - (sizeof(any->s.un.sun_path) - l);
    return AF_UNIX;
  }
  while(0);

  /* A DNS name and a port? */
  do
  {
    struct addrinfo* res;
    int port = 0;
    t = NULL;

    l = strlen(addr);
    if(l >= 255 || !isalpha(addr[0]))
      break;

    /* Some basic illegal character checks */
    if(strcspn(addr, " /\\") != l)
      break;

    strcpy(buf, addr);

    /* Find the last set that contains just numbers */
    t = strchr(buf, ':');
    if(t)
    {
      *t = 0;
      t++;
    }

    if(t)
    {
      port = strtol(t, &t2, 10);
      if(*t2 || port <= 0 || port >= 65536)
        break;
    }

    /* Try and resolve the domain name */
    if(getaddrinfo(buf, NULL, NULL, &res) != 0 || !res)
      break;

    memcpy(&(any->s.a), res->ai_addr, sizeof(struct sockaddr));
    any->namelen = res->ai_addrlen;
    freeaddrinfo(res);

    port = htons((unsigned short)(port <= 0 ? defport : port));

    switch(any->s.a.sa_family)
    {
    case PF_INET:
      any->s.in.sin_port = port;
      break;
#ifdef HAVE_INET6
    case PF_INET6:
      any->s.in6.sin6_port = port;
      break;
#endif
    };

    return any->s.a.sa_family;
  }
  while(0);

  return -1;
}

int sock_any_ntop(struct sockaddr_any* any, char* addr, size_t addrlen)
{
  int len = 0;

  switch(any->s.a.sa_family)
  {
  case AF_UNIX:
    len = strlen(any->s.un.sun_path);
    if(addrlen < len + 1)
    {
      errno = ENOSPC;
      return -1;
    }

    strcpy(addr, any->s.un.sun_path);
    break;

  case AF_INET:
    if(inet_ntop(any->s.a.sa_family, &(any->s.in.sin_addr), addr, addrlen) == NULL)
      return -1;
    break;

#ifdef HAVE_INET6
  case AF_INET6:
    if(inet_ntop(any->s.a.sa_family, &(any->s.in6.sin6_addr), addr, addrlen) == NULL)
      return -1;
    break;
#endif

  default:
    errno = EAFNOSUPPORT;
    return -1;
  }

  return 0;
}
