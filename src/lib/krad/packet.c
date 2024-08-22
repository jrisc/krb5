/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krad/packet.c - Packet functions for libkrad */
/*
 * Copyright 2013 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "internal.h"

#include <string.h>

#include <arpa/inet.h>

typedef unsigned char uchar;

/* RFC 2865 */
#define MSGAUTH_SIZE (2 + MD5_DIGEST_SIZE)
#define OFFSET_CODE 0
#define OFFSET_ID 1
#define OFFSET_LENGTH 2
#define OFFSET_AUTH 4
#define OFFSET_ATTR 20
#define OFFSET_RESP_MSGAUTH (OFFSET_ATTR + MSGAUTH_SIZE)
#define AUTH_FIELD_SIZE (OFFSET_ATTR - OFFSET_AUTH)

#define offset(d, o) (&(d)->data[o])
#define pkt_code_get(p) (*(krad_code *)offset(&(p)->pkt, OFFSET_CODE))
#define pkt_code_set(p, v) (*(krad_code *)offset(&(p)->pkt, OFFSET_CODE)) = v
#define pkt_id_get(p) (*(uchar *)offset(&(p)->pkt, OFFSET_ID))
#define pkt_id_set(p, v) (*(uchar *)offset(&(p)->pkt, OFFSET_ID)) = v
#define pkt_len_get(p)  load_16_be(offset(&(p)->pkt, OFFSET_LENGTH))
#define pkt_len_set(p, v)  store_16_be(v, offset(&(p)->pkt, OFFSET_LENGTH))
#define pkt_auth(p) ((uchar *)offset(&(p)->pkt, OFFSET_AUTH))
#define pkt_attr(p) ((unsigned char *)offset(&(p)->pkt, OFFSET_ATTR))

struct krad_packet_st {
    char buffer[KRAD_PACKET_SIZE_MAX];
    krad_attrset *attrset;
    krb5_data pkt;
};

typedef struct {
    uchar x[(UCHAR_MAX + 1) / 8];
} idmap;

/* Ensure the map is empty. */
static inline void
idmap_init(idmap *map)
{
    memset(map, 0, sizeof(*map));
}

/* Set an id as already allocated. */
static inline void
idmap_set(idmap *map, uchar id)
{
    map->x[id / 8] |= 1 << (id % 8);
}

/* Determine whether or not an id is used. */
static inline krb5_boolean
idmap_isset(const idmap *map, uchar id)
{
    return (map->x[id / 8] & (1 << (id % 8))) != 0;
}

/* Find an unused id starting the search at the value specified in id.
 * NOTE: For optimal security, the initial value of id should be random. */
static inline krb5_error_code
idmap_find(const idmap *map, uchar *id)
{
    krb5_int16 i;

    for (i = *id; i >= 0 && i <= UCHAR_MAX; (*id % 2 == 0) ? i++ : i--) {
        if (!idmap_isset(map, i))
            goto success;
    }

    for (i = *id; i >= 0 && i <= UCHAR_MAX; (*id % 2 == 1) ? i++ : i--) {
        if (!idmap_isset(map, i))
            goto success;
    }

    return ERANGE;

success:
    *id = i;
    return 0;
}

/* Generate size bytes of random data into the buffer. */
static inline krb5_error_code
randomize(krb5_context ctx, void *buffer, unsigned int size)
{
    krb5_data rdata = make_data(buffer, size);
    return krb5_c_random_make_octets(ctx, &rdata);
}

/* Generate a radius packet id. */
static krb5_error_code
id_generate(krb5_context ctx, krad_packet_iter_cb cb, void *data, uchar *id)
{
    krb5_error_code retval;
    const krad_packet *tmp;
    idmap used;
    uchar i;

    retval = randomize(ctx, &i, sizeof(i));
    if (retval != 0) {
        if (cb != NULL)
            (*cb)(data, TRUE);
        return retval;
    }

    if (cb != NULL) {
        idmap_init(&used);
        for (tmp = (*cb)(data, FALSE); tmp != NULL; tmp = (*cb)(data, FALSE))
            idmap_set(&used, tmp->pkt.data[1]);

        retval = idmap_find(&used, &i);
        if (retval != 0)
            return retval;
    }

    *id = i;
    return 0;
}

/* Generate a random authenticator field. */
static krb5_error_code
auth_generate_random(krb5_context ctx, uchar *rauth)
{
    krb5_ui_4 trunctime;
    time_t currtime;

    /* Get the least-significant four bytes of the current time. */
    currtime = time(NULL);
    if (currtime == (time_t)-1)
        return errno;
    trunctime = (krb5_ui_4)currtime;
    memcpy(rauth, &trunctime, sizeof(trunctime));

    /* Randomize the rest of the buffer. */
    return randomize(ctx, rauth + sizeof(trunctime),
                     AUTH_FIELD_SIZE - sizeof(trunctime));
}

/* Generate a response authenticator field. */
static krb5_error_code
auth_generate_response(krb5_context ctx, const char *secret,
                       const krad_packet *response, const uchar *auth,
                       uchar *rauth)
{
    krb5_error_code retval;
    krb5_checksum hash;
    krb5_data data;

    /* Allocate the temporary buffer. */
    retval = alloc_data(&data, response->pkt.length + strlen(secret));
    if (retval != 0)
        return retval;

    /* Encoded RADIUS packet with the request's
     * authenticator and the secret at the end. */
    memcpy(data.data, response->pkt.data, response->pkt.length);
    memcpy(data.data + OFFSET_AUTH, auth, AUTH_FIELD_SIZE);
    memcpy(data.data + response->pkt.length, secret, strlen(secret));

    /* Hash it. */
    retval = krb5_c_make_checksum(ctx, CKSUMTYPE_RSA_MD5, NULL, 0, &data,
                                  &hash);
    free(data.data);
    if (retval != 0)
        return retval;

    memcpy(rauth, hash.contents, AUTH_FIELD_SIZE);
    krb5_free_checksum_contents(ctx, &hash);
    return 0;
}

/* Create a new packet. */
static krad_packet *
packet_new(void)
{
    krad_packet *pkt;

    pkt = calloc(1, sizeof(krad_packet));
    if (pkt == NULL)
        return NULL;
    pkt->pkt = make_data(pkt->buffer, sizeof(pkt->buffer));

    return pkt;
}

/* Set the attrset object by decoding the packet. */
static krb5_error_code
packet_set_attrset(krb5_context ctx, const char *secret, krad_packet *pkt)
{
    krb5_data tmp;

    tmp = make_data(pkt_attr(pkt), pkt->pkt.length - OFFSET_ATTR);
    return kr_attrset_decode(ctx, &tmp, secret, pkt_auth(pkt), &pkt->attrset);
}

/* Determines if request or response requires a Message-Authenticator
 * attribute. */
inline static krb5_boolean
requires_msgauth(const char *secret, krad_code code)
{
    /* If no secret provided, make the assumption packets exchange will happen
     * on UNIX socket. Message-Authenticator is required only on UDP and TCP
     * connections. */
    if (!secret || 0 == strlen(secret))
        return FALSE;

    /* draft-ietf-radext-deprecating-radius-03 (section 7.2):
     *   RADIUS clients MUST include the Message-Authenticator in all
     *   Access-Request packets when UDP or TCP transport is used.
     *
     * draft-ietf-radext-deprecating-radius-03 (section 5.2.4):
     *   Servers MUST add Message-Authenticator as the first attribute in all
     *   responses to Access-Request packets. That is, all Access-Accept,
     *   Access-Reject, Access-Challenge, and Protocol-Error packets. */
    return code == krad_code_name2num("Access-Request")
        || code == krad_code_name2num("Access-Reject")
        || code == krad_code_name2num("Access-Accept")
        || code == krad_code_name2num("Access-Challenge")
        || code == krad_code_name2num("Protocol-Error");
}

/* Check if the packet has a Message-Authenticator attribute. */
inline static krb5_boolean
has_pkt_msgauth(const krad_packet *pkt)
{
    krad_attr msgauth_type;

    msgauth_type = krad_attr_name2num("Message-Authenticator");

    return NULL != krad_attrset_get(pkt->attrset, msgauth_type, 0);
}

/* Search for the beginning of the Message-Authenticator in the buffer of the
 * provided packet. */
static const unsigned char *
lookup_msgauth_addr(const krad_packet *pkt)
{
    krad_attr msgauth_type;
    size_t i;
    unsigned char *p;

    msgauth_type = krad_attr_name2num("Message-Authenticator");

    i = OFFSET_ATTR;
    while ((i + 2) < pkt->pkt.length) {
        p = (unsigned char *)offset(&pkt->pkt, i);
        if (msgauth_type == (krad_attr)*p)
            return p;
        i += p[1];
    }

    return NULL;
}

/* Calculate the signature of the packet ("pkt").
 *
 * If "auth" is not NULL, use this authenticator instead of the packet ("pkt")
 * one, and make the assuption that Message-Authenticator, is the first packet
 * attribute. */
static krb5_error_code
calculate_sign(const char *secret, const krad_packet *pkt,
               unsigned char auth[AUTH_FIELD_SIZE],
               unsigned char signature[MD5_DIGEST_SIZE])
{
    unsigned char zeroed_msgauth[MSGAUTH_SIZE], ksign_data[MD5_DIGEST_SIZE];
    krad_attr msgauth_type;
    const unsigned char *msgauth;
    krb5_crypto_iov input[5];
    krb5_data ksecr, ksign;
    krb5_error_code retval;

    /* Keep code, id, and length as they are. */
    input[0].flags = KRB5_CRYPTO_TYPE_DATA;
    input[0].data = make_data(pkt->pkt.data, OFFSET_AUTH);

    /* Use authenticator from the argument, or from the packet. */
    input[1].flags = KRB5_CRYPTO_TYPE_DATA;
    input[1].data = auth ? make_data(auth, AUTH_FIELD_SIZE)
                         : make_data(pkt_auth(pkt), AUTH_FIELD_SIZE);

    msgauth_type = krad_attr_name2num("Message-Authenticator");

    if (auth) {
        /* This is not an Access-Request signature. */
        if ((OFFSET_ATTR + MSGAUTH_SIZE) > pkt->pkt.length)
            return EMSGSIZE;
        if (msgauth_type != (krad_attr)*pkt_attr(pkt))
            return EBADMSG;

        /* draft-ietf-radext-deprecating-radius-03 (section 5.2.4):
         *   Servers MUST add Message-Authenticator as the first attribute
         *   in all responses to Access-Request packets. */
        msgauth = pkt_attr(pkt);
    } else {
        /* This is an Access-Request signature. */
        msgauth = lookup_msgauth_addr(pkt);
        if (!msgauth)
            return EINVAL;
    }

    /* Read attributes before Message-Authenticator (if any). */
    input[2].flags = KRB5_CRYPTO_TYPE_DATA;
    input[2].data = make_data(pkt_attr(pkt), msgauth - pkt_attr(pkt));

    /* Read zeroed Message-Authenticator.
     *
     * RFC2869 (section 5.14):
     *   When the checksum is calculated the signature string should be
     *   considered to be sixteen octets of zero. */
    zeroed_msgauth[0] = msgauth_type;
    zeroed_msgauth[1] = MSGAUTH_SIZE;
    memset(zeroed_msgauth + 2, 0, MD5_DIGEST_SIZE);

    input[3].flags = KRB5_CRYPTO_TYPE_DATA;
    input[3].data = make_data(zeroed_msgauth, MSGAUTH_SIZE);

    /* Read attributes after Message-Authenticator (if any). */
    input[4].flags = KRB5_CRYPTO_TYPE_DATA;
    input[4].data = make_data((void *)(msgauth + MSGAUTH_SIZE),
        (pkt->pkt.data + pkt->pkt.length) - (char*)(msgauth + MSGAUTH_SIZE));

    ksign = make_data(ksign_data, MD5_DIGEST_SIZE);
    ksecr = make_data((char *)secret, strlen(secret));

    retval = k5_rfc2104_hmacmd5_checksum(&ksecr, input, 5, &ksign);
    if (retval)
        return retval;

    memcpy(signature, ksign.data, MD5_DIGEST_SIZE);

    return retval;
}

/* Copy an attribute set and add a zeroed Message-Authenticator attribute to the
 * copy. */
static krb5_error_code
clone_attrs_plus_zeroed_msgauth(const krad_attrset *orig, krad_attrset **copy)
{
    char zeroed_signature[MD5_DIGEST_SIZE] = {0};
    krb5_data msgauth;
    krad_attr msgauth_type;
    krb5_error_code retval;

    msgauth_type = krad_attr_name2num("Message-Authenticator");

    /* Make sure the original attribute set does not contain any
     * Message-Authenticator. */
    if (krad_attrset_get(orig, msgauth_type, 0))
        return EINVAL;

    /* Create zeroed Message-Authenticator attribute. */
    msgauth = make_data(zeroed_signature, MD5_DIGEST_SIZE);

    /* Copy attribute set. */
    retval = krad_attrset_copy(orig, copy);
    if (retval)
        return retval;

    /* Add Message-Authenticator to attribute set. */
    retval = krad_attrset_add(*copy, msgauth_type, &msgauth);

    return retval;
}

ssize_t
krad_packet_bytes_needed(const krb5_data *buffer)
{
    size_t len;

    if (buffer->length < OFFSET_AUTH)
        return OFFSET_AUTH - buffer->length;

    len = load_16_be(offset(buffer, OFFSET_LENGTH));
    if (len > KRAD_PACKET_SIZE_MAX)
        return -1;

    return (buffer->length > len) ? 0 : len - buffer->length;
}

void
krad_packet_free(krad_packet *pkt)
{
    if (pkt)
        krad_attrset_free(pkt->attrset);
    free(pkt);
}

/* Create a new request packet. */
krb5_error_code
krad_packet_new_request(krb5_context ctx, const char *secret, krad_code code,
                        const krad_attrset *set, krad_packet_iter_cb cb,
                        void *data, krad_packet **request)
{
    krb5_error_code retval;
    krad_packet *pkt;
    uchar id;
    size_t attrset_len;
    krad_attrset *attrs_copy = NULL;
    krb5_boolean msgauth_required;

    pkt = packet_new();
    if (pkt == NULL) {
        if (cb != NULL)
            (*cb)(data, TRUE);
        retval = ENOMEM;
        goto cleanup;
    }

    /* Generate the ID. */
    retval = id_generate(ctx, cb, data, &id);
    if (retval != 0)
        goto cleanup;
    pkt_id_set(pkt, id);

    /* Generate the authenticator. */
    retval = auth_generate_random(ctx, pkt_auth(pkt));
    if (retval != 0)
        goto cleanup;

    /* Determine if Message-Authenticator is required. */
    msgauth_required = secret && 0 < strlen(secret)
                       && code == krad_code_name2num("Access-Request");

    if (msgauth_required) {
        /* Add zeroed Message-Authenticator attribute. */
        retval = clone_attrs_plus_zeroed_msgauth(set, &attrs_copy);
        if (retval != 0)
            goto cleanup;

        set = attrs_copy;
    }

    /* Encode the attributes. */
    retval = kr_attrset_encode(set, secret, pkt_auth(pkt), pkt_attr(pkt),
                               &attrset_len);
    if (retval != 0)
        goto cleanup;

    /* Set the code, ID and length. */
    pkt->pkt.length = attrset_len + OFFSET_ATTR;
    pkt_code_set(pkt, code);
    pkt_len_set(pkt, pkt->pkt.length);

    if (msgauth_required) {
        /* Calculate and set actual Message-Authenticator signature. */
        retval = calculate_sign(secret, pkt, NULL, pkt_attr(pkt) + 2);
        if (retval != 0)
            goto cleanup;
    }

    /* Copy the attrset for future use. */
    retval = packet_set_attrset(ctx, secret, pkt);
    if (retval != 0)
        goto cleanup;

    *request = pkt;

cleanup:
    if (retval != 0)
        free(pkt);
    if (attrs_copy)
        krad_attrset_free(attrs_copy);

    return retval;
}

/* Create a new request packet. */
krb5_error_code
krad_packet_new_response(krb5_context ctx, const char *secret, krad_code code,
                         const krad_attrset *set, const krad_packet *request,
                         krad_packet **response)
{
    krb5_error_code retval;
    krad_packet *pkt;
    size_t attrset_len;
    krad_attrset *attrs_copy = NULL;
    krb5_boolean msgauth_required;

    pkt = packet_new();
    if (pkt == NULL)
        return ENOMEM;

    /* Determine if Message-Authenticator is required. */
    msgauth_required = requires_msgauth(secret, code);

    if (msgauth_required) {
        /* Add zeroed Message-Authenticator attribute. */
        retval = clone_attrs_plus_zeroed_msgauth(set, &attrs_copy);
        if (retval != 0)
            goto cleanup;

        set = attrs_copy;
    }

    /* Encode the attributes. */
    retval = kr_attrset_encode(set, secret, pkt_auth(request), pkt_attr(pkt),
                               &attrset_len);
    if (retval != 0)
        goto cleanup;

    /* Set the code, ID and length. */
    pkt->pkt.length = attrset_len + OFFSET_ATTR;
    pkt_code_set(pkt, code);
    pkt_id_set(pkt, pkt_id_get(request));
    pkt_len_set(pkt, pkt->pkt.length);

    /* Generate the authenticator. */
    retval = auth_generate_response(ctx, secret, pkt, pkt_auth(request),
                                    pkt_auth(pkt));
    if (retval != 0)
        goto cleanup;

    /* Copy the attrset for future use. */
    retval = packet_set_attrset(ctx, secret, pkt);
    if (retval != 0)
        goto cleanup;

    if (msgauth_required) {
        /* Calculate and set actual Message-Authenticator signature.
         * Use authenticator from the request, not from the response.
         *
         * RFC2869 (section 5.14):
         *   For Access-Challenge, Access-Accept, and Access-Reject packets, the
         *   Message-Authenticator is calculated [...] using the
         *   Request-Authenticator from the Access-Request this packet is in
         *   reply to. */
        retval = calculate_sign(secret, pkt, pkt_auth(request),
                                pkt_attr(pkt) + 2);
        if (retval != 0)
            goto cleanup;
    }

    *response = pkt;

cleanup:
    if (retval != 0)
        free(pkt);
    krad_attrset_free(attrs_copy);

    return retval;
}

/* Verify packet using the signature provided in Message-Authenticator
 * attribute.
 *
 * - If Access-Request, set "req" and leave "rsp" as NULL.
 * - Otherwise, set "rsp" with the packet to verify, and set "req" with the
 *   initial Access-Request packet. */
static krb5_error_code
verify_msgauth(const char *secret, const krad_packet *req,
               const krad_packet *rsp)
{
    unsigned char signature[MD5_DIGEST_SIZE];
    krad_attr msgauth_type;
    const krb5_data *msgauth;
    krb5_error_code retval;

    msgauth_type = krad_attr_name2num("Message-Authenticator");
    msgauth = krad_packet_get_attr(rsp, msgauth_type, 0);
    if (!msgauth)
        return ENODATA;

    if (rsp) {
        retval = calculate_sign(secret, rsp, pkt_auth(req), signature);
    } else {
        retval = calculate_sign(secret, req, NULL, signature);
    }
    if (retval)
        return retval;

    if (msgauth->length != MD5_DIGEST_SIZE)
        return EMSGSIZE;

    if (0 != memcmp(signature, msgauth->data, MD5_DIGEST_SIZE))
        return EBADMSG;

    return 0;
}

/* Decode a packet. */
static krb5_error_code
decode_packet(krb5_context ctx, const char *secret, const krb5_data *buffer,
              krad_packet **pkt)
{
    krb5_error_code retval;
    krad_packet *tmp;
    krb5_ui_2 len;

    tmp = packet_new();
    if (tmp == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Ensure a proper message length. */
    retval = (buffer->length < OFFSET_ATTR) ? EMSGSIZE : 0;
    if (retval != 0)
        goto error;
    len = load_16_be(offset(buffer, OFFSET_LENGTH));
    retval = (len < OFFSET_ATTR) ? EBADMSG : 0;
    if (retval != 0)
        goto error;
    retval = (len > buffer->length || len > tmp->pkt.length) ? EBADMSG : 0;
    if (retval != 0)
        goto error;

    /* Copy over the buffer. */
    tmp->pkt.length = len;
    memcpy(tmp->pkt.data, buffer->data, len);

    /* Parse the packet to ensure it is well-formed. */
    retval = packet_set_attrset(ctx, secret, tmp);
    if (retval != 0)
        goto error;

    *pkt = tmp;
    return 0;

error:
    krad_packet_free(tmp);
    return retval;
}

krb5_error_code
krad_packet_decode_request(krb5_context ctx, const char *secret,
                           const krb5_data *buffer, krad_packet_iter_cb cb,
                           void *data, const krad_packet **duppkt,
                           krad_packet **reqpkt)
{
    const krad_packet *tmp = NULL;
    krb5_error_code retval;

    retval = decode_packet(ctx, secret, buffer, reqpkt);
    if (cb != NULL && retval == 0) {
        while ((tmp = (*cb)(data, FALSE)) != NULL) {
            if (pkt_id_get(*reqpkt) != pkt_id_get(tmp))
                continue;

            /* Verify Message-Authenticator if present. */
            if (has_pkt_msgauth(tmp)) {
                retval = verify_msgauth(secret, tmp, NULL);
            } else if (requires_msgauth(secret, pkt_code_get(tmp))) {
                retval = ENODATA;
            }

            break;
        }
    }

    if (cb != NULL && (retval != 0 || tmp != NULL))
        (*cb)(data, TRUE);

    if (retval == 0)
        *duppkt = tmp;
    return retval;
}

krb5_error_code
krad_packet_decode_response(krb5_context ctx, const char *secret,
                            const krb5_data *buffer, krad_packet_iter_cb cb,
                            void *data, const krad_packet **reqpkt,
                            krad_packet **rsppkt)
{
    uchar auth[AUTH_FIELD_SIZE];
    const krad_packet *req = NULL;
    krad_packet *rsp = NULL;
    krb5_error_code retval;

    retval = decode_packet(ctx, secret, buffer, &rsp);
    if (retval != 0)
        goto cleanup;

    if (cb != NULL) {
        while ((req = (*cb)(data, FALSE)) != NULL) {
            if (pkt_id_get(rsp) != pkt_id_get(req))
                continue;

            /* Response */
            retval = auth_generate_response(ctx, secret, rsp, pkt_auth(req),
                                            auth);
            if (retval != 0)
                goto cleanup;

            /* If the authenticator matches, then the response is valid. */
            if (memcmp(pkt_auth(rsp), auth, sizeof(auth)) != 0)
                continue;

            /* Verify Message-Authenticator if present. */
            if (has_pkt_msgauth(rsp)) {
                retval = verify_msgauth(secret, req, rsp);
                if (retval != 0)
                    goto cleanup;
            } else if (requires_msgauth(secret, pkt_code_get(rsp))) {
                retval = ENODATA;
                goto cleanup;
            }

            break;
        }
    }

    *reqpkt = req;
    *rsppkt = rsp;

cleanup:
    if (cb != NULL && (retval != 0 || req != NULL))
        (*cb)(data, TRUE);
    if (retval != 0)
        krad_packet_free(rsp);

    return retval;
}

const krb5_data *
krad_packet_encode(const krad_packet *pkt)
{
    return &pkt->pkt;
}

krad_code
krad_packet_get_code(const krad_packet *pkt)
{
    if (pkt == NULL)
        return 0;

    return pkt_code_get(pkt);
}

const krb5_data *
krad_packet_get_attr(const krad_packet *pkt, krad_attr type, size_t indx)
{
    return krad_attrset_get(pkt->attrset, type, indx);
}
