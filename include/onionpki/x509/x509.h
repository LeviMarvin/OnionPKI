/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_X509_H
#define ONIONPKI_X509_H

#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/x509v3err.h>
#include <onionpki/stderr.h>

int x509_name_set_data(X509_NAME *name, const char *CN, const char *C, const char *ST, const char *L, const char *O,
                       const char *OU, const char *E, int is_ev, const char *sN, const char *bC, const char *jC,
                       const char *jST, const char *jL);

#endif //ONIONPKI_X509_H
