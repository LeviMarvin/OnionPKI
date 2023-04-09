/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_CERT_X509_V3_H
#define ONIONPKI_CERT_X509_V3_H

#include <onionpki/x509/x509.h>
#include <onionpki/x509/ext.h>
#include <onionpki/stdonion.h>
#include <onionpki/stderr.h>

int cert_v3_new(X509 *crt, X509_NAME *subject, unsigned long serial, int days, EVP_PKEY *pkey);
int cert_v3_sign(X509 *cert, const X509 *issuer_cert, EVP_PKEY *issuer_key, int md);
int cert_revoke(X509_REVOKED *revoked, X509 *cert, time_t revoke_time, int reason);

#endif //ONIONPKI_CERT_X509_V3_H