/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#include "onionpki/key/rsa.h"

int key_rsa_new(EVP_PKEY *pkey, int bits)
{
    int rc;
    // check input
    if (pkey == NULL) {
        return -ERROBJNULL;
    }
    if (bits == 0)
        bits = 2048;

    EVP_PKEY_CTX *pCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    rc = EVP_PKEY_keygen_init(pCtx);
    if (!rc) {
        return -ERROSSL;
    }
    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(pCtx, bits);
    if (!rc) {
        return -ERROSSL;
    }
    rc = EVP_PKEY_keygen(pCtx, &pkey);
    if (!rc) {
        return -ERROSSL;
    }

    return rc;
}