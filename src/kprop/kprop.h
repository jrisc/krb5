/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kprop/kprop.h */
/*
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#define KPROP_SERVICE_NAME "host"
#define TGT_SERVICE_NAME "krbtgt"
#define KPROP_SERVICE "krb5_prop"
#define KPROP_PORT 754

#define KPROP_PROT_VERSION "kprop5_01"

#define KPROP_BUFSIZ 32768
#define KPROP_DBSIZE_BUFSIZ (sizeof(krb5_ui_4) + sizeof(uint64_t))

/* pathnames are in osconf.h, included via k5-int.h */

int sockaddr2krbaddr(krb5_context context, int family, struct sockaddr *sa,
                     krb5_address **dest);

krb5_error_code
sn2princ_realm(krb5_context context, const char *hostname, const char *sname,
               const char *realm, krb5_principal *princ_out);

/*
 * Write database size on 4 bytes, or if 0 or larger than 32^2-1 (4 GiB - 1 B),
 * set 4 first bytes to 0 and write size on the 8 next bytes.
 *
 * This behavior is meant to ensure compatibility with previous versions.
 *
 * buf->data must be allocated with size of at least KPROP_DBSIZE_BUFSIZ
 */
void encode_database_size(uint64_t size, krb5_data *buf);

/*
 * Read database size from 4 first bytes. If the value is 0, read the actual
 * size from the 8 next bytes.
 *
 * This behavior is meant to ensure compatibility with previous versions.
 */
uint64_t decode_database_size(const krb5_data *buf);
