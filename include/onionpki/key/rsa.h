/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_RSA_H
#define ONIONPKI_RSA_H

#include <openssl/rsa.h>
#include <openssl/rsaerr.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <onionpki/stderr.h>

int key_rsa_new(EVP_PKEY *pkey, int bits);

#endif //ONIONPKI_RSA_H
