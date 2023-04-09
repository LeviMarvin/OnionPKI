/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#include <onionpki/stdonion.h>

const char *onion_version(void)
{
    return "0.1.0";
}

const EVP_MD *onion_evp_md_get_by_code(int md)
{
    switch (md) {
        case 0:
            return EVP_sha1();
        case 1:
            return EVP_sha256();
        case 2:
            return EVP_sha384();
        case 3:
            return EVP_sha512();
        case 10:
            return EVP_md5();
        default:
            return EVP_sha256();
    }
}
