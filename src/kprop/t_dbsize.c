/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kprop/t_dbsize.c - Unit tests for KDC DB size serialization */
/*
 * Copyright (C) 2022 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"

#include <assert.h>

#include "kprop.h"

struct test {
    uint64_t dbsize;
    unsigned int written;
    char *data;
};

struct test cases[] = {
    {           0, 12, "\x00\x00\x00\x00""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {           1,  4, "\x00\x00\x00\x01""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {      0xFFFF,  4, "\x00\x00\xFF\xFF""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {  0x7FFFFFFF,  4, "\x7F\xFF\xFF\xFF""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {  0x80000000,  4, "\x80\x00\x00\x00""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {  0xFFFF0000,  4, "\xFF\xFF\x00\x00""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {  0xFFFFFFFE,  4, "\xFF\xFF\xFF\xFE""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {  0xFFFFFFFF,  4, "\xFF\xFF\xFF\xFF""\x00\x00\x00\x00\x00\x00\x00\x00" },
    {  UINT32_MAX,  4, "\xFF\xFF\xFF\xFF""\x00\x00\x00\x00\x00\x00\x00\x00" },
    { 0x100000000, 12, "\x00\x00\x00\x00""\x00\x00\x00\x01\x00\x00\x00\x00" },
    { UINT32_MAX + UINT64_C(1),
                   12, "\x00\x00\x00\x00""\x00\x00\x00\x01\x00\x00\x00\x00" },
    { 0x7FFFFFFFFFFFFFFF,
                   12, "\x00\x00\x00\x00""\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF" },
    { 0x8000000000000000,
                   12, "\x00\x00\x00\x00""\x80\x00\x00\x00\x00\x00\x00\x00" },
    { 0xFFFFFFFFFFFFFFFE,
                   12, "\x00\x00\x00\x00""\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE" },
    { 0xFFFFFFFF00000000,
                   12, "\x00\x00\x00\x00""\xFF\xFF\xFF\xFF\x00\x00\x00\x00" },
    { 0xFFFFFFFFFFFFFFFF,
                   12, "\x00\x00\x00\x00""\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" },
    {  UINT64_MAX, 12, "\x00\x00\x00\x00""\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" },
};

struct test impossible_cases[] = {
    { 1,          12, "\x00\x00\x00\x00""\x00\x00\x00\x00\x00\x00\x00\x01" },
    { 0xFFFF,     12, "\x00\x00\x00\x00""\x00\x00\x00\x00\x00\x00\xFF\xFF" },
    { 0x80000000, 12, "\x00\x00\x00\x00""\x00\x00\x00\x00\x80\x00\x00\x00" },
    { 0xFFFF0000, 12, "\x00\x00\x00\x00""\x00\x00\x00\x00\xFF\xFF\x00\x00" },
    { 0xFFFFFFFF, 12, "\x00\x00\x00\x00""\x00\x00\x00\x00\xFF\xFF\xFF\xFF" },
};

int main()
{
    krb5_data data;
    struct test *test;
    uint64_t decoded_dbsize;
    size_t i, n = sizeof(cases) / sizeof(cases[0]);
    uint8_t dbsize_buf[KPROP_DBSIZE_BUFSIZ];

    assert(KPROP_DBSIZE_BUFSIZ == 12);

    for (i = 0; test = cases + i, i < n; ++i) {
        /* Test DB size encoding */
        data.length = 0;
        data.data = memset(dbsize_buf, 0, KPROP_DBSIZE_BUFSIZ);

        encode_database_size(test->dbsize, &data);

        assert(test->written == data.length);
        assert(0 == memcmp(test->data, data.data, test->written));

        /* Test DB size decoding */
        data.length = 0;
        data.data = test->data;

        decoded_dbsize = decode_database_size(&data);

        assert(0 == data.length);
        assert(test->dbsize == decoded_dbsize);
    }

    /* Valid encodings to read, but should never occur in practice */
    n = sizeof(impossible_cases) / sizeof(impossible_cases[0]);
    for (i = 0; test = impossible_cases + i, i < n; ++i) {
        /* Test DB size encoding */
        data.length = 0;
        data.data = memset(dbsize_buf, 0, KPROP_DBSIZE_BUFSIZ);

        encode_database_size(test->dbsize, &data);

        assert(test->written > data.length);
        assert(0 != memcmp(test->data, data.data, test->written));

        /* Test DB size decoding */
        data.length = 0;
        data.data = test->data;

        decoded_dbsize = decode_database_size(&data);

        assert(0 == data.length);
        assert(test->dbsize == decoded_dbsize);
    }
}
