/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_CRL_V2_H
#define ONIONPKI_CRL_V2_H

#include <onionpki/x509/x509.h>
#include <onionpki/x509/ext.h>
#include <onionpki/stdonion.h>
#include <onionpki/stderr.h>

int crl_add_revoked(X509_CRL *crl, X509_REVOKED *revoked);
int crl_v2_new(X509_CRL *crl, int next_days, long crlNumber);
int crl_sign(X509_CRL *crl, X509 *issuer_cert, EVP_PKEY *issuer_key, int md);

#endif //ONIONPKI_CRL_V2_H
