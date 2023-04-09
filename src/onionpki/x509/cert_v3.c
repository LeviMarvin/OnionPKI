/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#include <onionpki/x509/cert_v3.h>

int cert_v3_new(X509 *crt, X509_NAME *subject, unsigned long serial, int days, EVP_PKEY *pkey)
{
    // check input
    if (crt == NULL || subject == NULL || pkey == NULL) {
        return -ERROBJNULL;
    }
    // prepare serial number.
    ASN1_INTEGER *asn1_serial = ASN1_INTEGER_new();
    ASN1_INTEGER_set_uint64(asn1_serial, serial);
    // prepare time.
    time_t time_now = time(NULL);
    ASN1_TIME *not_before_time = ASN1_TIME_new();
    ASN1_TIME *not_after_time = ASN1_TIME_new();
    ASN1_TIME_set(not_before_time, time_now);
    ASN1_TIME_adj(not_after_time, time_now, days, 0);

    X509_set_version(crt, 2);
    X509_set_serialNumber(crt, asn1_serial);
    X509_set1_notBefore(crt, not_before_time);
    X509_set1_notAfter(crt, not_after_time);
    X509_set_subject_name(crt, subject);

    // add custom extension, oid=1.2.3.4.5.7
    /*X509_EXTENSION *ext_custom = X509_EXTENSION_new();
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(oct, 0x00, 1);
    ext_new(ext_custom, 0, "1.2.3.4.5.7", oct);
    X509_add_ext(crt, ext_custom, -1);*/

    // bind public key to cert
    X509_set_pubkey(crt, pkey);

    ASN1_STRING_free(asn1_serial);
    ASN1_TIME_free(not_before_time);
    ASN1_TIME_free(not_after_time);
    /*X509_EXTENSION_free(ext_custom);
    ASN1_OCTET_STRING_free(oct);*/

    return 0;
}

int cert_v3_sign(X509 *cert, const X509 *issuer_cert, EVP_PKEY *issuer_key, int md)
{
    if (cert == NULL || issuer_cert == NULL || issuer_key == NULL) {
        return -ERROBJNULL;
    }

    const EVP_MD *evp_md = onion_evp_md_get_by_code(md);

    X509_NAME *issuer_name = X509_NAME_dup(X509_get_subject_name(issuer_cert));
    X509_set_issuer_name(cert, issuer_name);

    X509_EXTENSION *ext_ski = X509_EXTENSION_new();
    ext_subject_keyid_new(ext_ski, cert);
    X509_add_ext(cert, ext_ski, 0);

    X509_EXTENSION *ext_aki = X509_EXTENSION_new();
    ext_authority_keyid_new(ext_aki, issuer_cert);
    X509_add_ext(cert, ext_aki, 1);

    X509_sign(cert, issuer_key, evp_md);

    X509_NAME_free(issuer_name);
    X509_EXTENSION_free(ext_ski);
    X509_EXTENSION_free(ext_aki);
    return 0;
}

int cert_revoke(X509_REVOKED *revoked, X509 *cert, time_t revoke_time, int reason)
{
    if (revoked == NULL || cert == NULL) {
        return -ERROBJNULL;
    }

    ASN1_TIME *revoked_time = ASN1_TIME_new();
    ASN1_TIME_set(revoked_time, revoke_time);

    X509_REVOKED_set_serialNumber(revoked, (ASN1_INTEGER *) X509_get0_serialNumber(cert));
    X509_REVOKED_set_revocationDate(revoked, revoked_time);
    // Add CRL Reason Code
    unsigned char *byte_enumerated = NULL;
    int byte_enumerated_len;
    ASN1_ENUMERATED *enumerated = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set_int64(enumerated, reason);
    byte_enumerated_len = i2d_ASN1_ENUMERATED(enumerated, &byte_enumerated);
    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet_string, byte_enumerated, byte_enumerated_len);
    X509_EXTENSION *ext_crc = X509_EXTENSION_new();
    ext_crc = X509_EXTENSION_create_by_NID(&ext_crc, NID_crl_reason, 0, octet_string);
    X509_REVOKED_add_ext(revoked, ext_crc, -1);

    ASN1_TIME_free(revoked_time);
    ASN1_ENUMERATED_free(enumerated);
    ASN1_OCTET_STRING_free(octet_string);
    X509_EXTENSION_free(ext_crc);
    return 0;
}