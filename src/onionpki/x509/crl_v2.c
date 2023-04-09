/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#include <onionpki/x509/crl_v2.h>

int crl_add_revoked(X509_CRL *crl, X509_REVOKED *revoked)
{
    if (crl == NULL ) {
        return -ERROBJNULL;
    }

    X509_CRL_add0_revoked(crl, revoked);

    return 0;
}

int crl_v2_new(X509_CRL *crl, int next_days, long crlNumber)
{
    if (crl == NULL) {
        return -ERROBJNULL;
    }
    // prepare extension crl_number

    X509_EXTENSION *ext_crlNumber = NULL;
    ASN1_INTEGER *asn1_crlNumber = ASN1_INTEGER_new();
    ASN1_OCTET_STRING *asn1_octet_crlNumber = ASN1_OCTET_STRING_new();
    ASN1_INTEGER_set(asn1_crlNumber, crlNumber);
    unsigned char *ext_data = NULL;
    int ext_data_len = i2d_ASN1_INTEGER(asn1_crlNumber, &ext_data);
    ASN1_OCTET_STRING_set(asn1_octet_crlNumber, ext_data, ext_data_len);
    ext_crlNumber = X509_EXTENSION_create_by_NID(NULL, NID_crl_number, 0, asn1_octet_crlNumber);

    X509_CRL_set_version(crl, 1); // v2
    // prepare time.
    time_t time_now = time(NULL);
    ASN1_TIME *last_time = ASN1_TIME_new();
    ASN1_TIME *next_time = ASN1_TIME_new();
    ASN1_TIME_set(last_time, time_now);
    ASN1_TIME_adj(next_time, time_now, next_days, 0);
    X509_CRL_set1_lastUpdate(crl, last_time);
    X509_CRL_set1_nextUpdate(crl, next_time);
    X509_CRL_add_ext(crl, ext_crlNumber, -1);

    ASN1_TIME_free(last_time);
    ASN1_TIME_free(next_time);
    ASN1_INTEGER_free(asn1_crlNumber);
    ASN1_OCTET_STRING_free(asn1_octet_crlNumber);
    X509_EXTENSION_free(ext_crlNumber);
    return 0;
}

int crl_sign(X509_CRL *crl, X509 *issuer_cert, EVP_PKEY *issuer_key, int md)
{
    if (crl == NULL || issuer_cert == NULL || issuer_key == NULL) {
        return -ERROBJNULL;
    }

    const EVP_MD *evp_md = onion_evp_md_get_by_code(md);
    // prepare issue information
    X509_NAME *issuer_name = X509_get_issuer_name(issuer_cert);
    X509_CRL_set_issuer_name(crl, issuer_name);

    X509_EXTENSION *ext_aki = X509_EXTENSION_new();
    ext_authority_keyid_new(ext_aki, issuer_cert);
    X509_CRL_add_ext(crl, ext_aki, 0);

    X509_CRL_sign(crl, issuer_key, evp_md);

    return 0;
}