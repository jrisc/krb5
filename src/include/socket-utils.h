/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2001,2005 by the Massachusetts Institute of Technology,
 * Cambridge, MA, USA.  All Rights Reserved.
 *
 * This software is being provided to you, the LICENSEE, by the
 * Massachusetts Institute of Technology (M.I.T.) under the following
 * license.  By obtaining, using and/or copying this software, you agree
 * that you have read, understood, and will comply with these terms and
 * conditions:
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify and distribute
 * this software and its documentation for any purpose and without fee or
 * royalty is hereby granted, provided that you agree to comply with the
 * following copyright notice and statements, including the disclaimer, and
 * that the same appear on ALL copies of the software and documentation,
 * including modifications that you make for internal use or for
 * distribution:
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", AND M.I.T. MAKES NO REPRESENTATIONS
 * OR WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not
 * limitation, M.I.T. MAKES NO REPRESENTATIONS OR WARRANTIES OF
 * MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF
 * THE LICENSED SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY
 * PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
 *
 * The name of the Massachusetts Institute of Technology or M.I.T. may NOT
 * be used in advertising or publicity pertaining to distribution of the
 * software.  Title to copyright in this software and any associated
 * documentation shall at all times remain with M.I.T., and USER agrees to
 * preserve same.
 *
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 */

#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdbool.h>

/* Some useful stuff cross-platform for manipulating socket addresses.
   We assume at least ipv4 sockaddr_in support.  The sockaddr_storage
   stuff comes from the ipv6 socket api enhancements; socklen_t is
   provided on some systems; the rest is just convenience for internal
   use in the krb5 tree.

   Do NOT install this file.  */

/* for HAVE_SOCKLEN_T etc */
#include "autoconf.h"
/* for sockaddr_storage */
#include "port-sockets.h"
/* for "inline" if needed */
#include "k5-platform.h"

/*
 * There's a lot of confusion between pointers to different sockaddr
 * types, and pointers with different degrees of indirection, as in
 * the locate_kdc type functions.  Use these function to ensure we
 * don't do something silly like cast a "sockaddr **" to a
 * "sockaddr_in *".
 *
 * The casts to (void *) are to get GCC to shut up about alignment
 * increasing.  We assume that struct sockaddr pointers are generally
 * read-only; there are a few exceptions, but they all go through
 * sa_setport().
 */
static inline const struct sockaddr_in *sa2sin(const struct sockaddr *sa)
{
    return (const struct sockaddr_in *)(void *)sa;
}
static inline const struct sockaddr_in6 *sa2sin6(const struct sockaddr *sa)
{
    return (const struct sockaddr_in6 *)(void *)sa;
}
static inline struct sockaddr *ss2sa (struct sockaddr_storage *ss)
{
    return (struct sockaddr *) ss;
}
static inline struct sockaddr_in *ss2sin (struct sockaddr_storage *ss)
{
    return (struct sockaddr_in *) ss;
}
static inline struct sockaddr_in6 *ss2sin6 (struct sockaddr_storage *ss)
{
    return (struct sockaddr_in6 *) ss;
}
#ifndef _WIN32
static inline const struct sockaddr_un *sa2sun(const struct sockaddr *sa)
{
    return (const struct sockaddr_un *)(void *)sa;
}
static inline struct sockaddr_un *ss2sun(struct sockaddr_storage *ss)
{
    return (struct sockaddr_un *)ss;
}
#endif

/* Set the IPv4 or IPv6 port on sa to port.  Do nothing if sa is not an
 * Internet socket. */
static inline void
sa_setport(struct sockaddr *sa, uint16_t port)
{
    if (sa->sa_family == AF_INET)
        ((struct sockaddr_in *)sa2sin(sa))->sin_port = htons(port);
    else if (sa->sa_family == AF_INET6)
        ((struct sockaddr_in6 *)sa2sin6(sa))->sin6_port = htons(port);
}

/* Get the Internet port number of sa, or 0 if it is not an Internet socket. */
static inline uint16_t
sa_getport(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return ntohs(sa2sin(sa)->sin_port);
    else if (sa->sa_family == AF_INET6)
        return ntohs(sa2sin6(sa)->sin6_port);
    else
        return 0;
}

/* Return true if sa is an IPv4 or IPv6 socket address. */
static inline int
sa_is_inet(const struct sockaddr *sa)
{
    return sa->sa_family == AF_INET || sa->sa_family == AF_INET6;
}

/* Return true if sa is an IPv4 or IPv6 wildcard address. */
static inline int
sa_is_wildcard(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET6)
        return IN6_IS_ADDR_UNSPECIFIED(&sa2sin6(sa)->sin6_addr);
    else if (sa->sa_family == AF_INET)
        return sa2sin(sa)->sin_addr.s_addr == INADDR_ANY;
    return 0;
}

/* Return the length of an IPv4 or IPv6 socket structure; abort if it is
 * neither. */
static inline socklen_t
sa_socklen(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET6)
        return sizeof(struct sockaddr_in6);
    else if (sa->sa_family == AF_INET)
        return sizeof(struct sockaddr_in);
#ifndef _WIN32
    else if (sa->sa_family == AF_UNIX)
        return sizeof(struct sockaddr_un);
#endif
    else
        abort();
}

/* Return true if a and b are the same address (and port if applicable). */
static inline bool
sa_equal(const struct sockaddr *a, const struct sockaddr *b)
{
    if (a == NULL || b == NULL || a->sa_family != b->sa_family)
        return false;

    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *x = sa2sin(a);
        const struct sockaddr_in *y = sa2sin(b);

        if (x->sin_port != y->sin_port)
            return false;
        return memcmp(&x->sin_addr, &y->sin_addr, sizeof(x->sin_addr)) == 0;
    } else if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *x = sa2sin6(a);
        const struct sockaddr_in6 *y = sa2sin6(b);

        if (x->sin6_port != y->sin6_port)
            return false;
        return memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0;
#ifndef _WIN32
    } else if (a->sa_family == AF_UNIX) {
        const struct sockaddr_un *x = sa2sun(a);
        const struct sockaddr_un *y = sa2sun(b);

        return strcmp(x->sun_path, y->sun_path) == 0;
#endif
    }

    return false;
}

#endif /* SOCKET_UTILS_H */
