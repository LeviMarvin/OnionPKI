/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#include <onionpki/x509/ext.h>

int ext_new(X509_EXTENSION *ext, int is_crit, const char *oid,
            struct asn1_string_st *data)
{
    // check input
    if (ext == NULL || oid == NULL || data == NULL) {
        return -ERROBJNULL;
    }
    if (!strcmp(oid, "")) {
        return -ERRSTRNULL;
    }

    ASN1_OBJECT* obj = OBJ_txt2obj(oid, 0);
    if (obj == NULL) {
        return -ERROBJNULL;
    }

    if (is_crit) {
        is_crit = 1;
    }

    X509_EXTENSION_create_by_OBJ(&ext, obj, is_crit, data);

    ASN1_OBJECT_free(obj);

    if (ext == NULL) {
        return -ERROSSL;
    }
    return 0;
}

/*
 * @brief Create a new Subject Key Id X509 extension.
 * @param ext The X509 extension to create.
 * @param cert_key The public key of the certificate.
 */
int ext_subject_keyid_new(X509_EXTENSION *ext, X509 *cert)
{
    if (ext == NULL || cert == NULL) {
        return -ERROBJNULL;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char *ext_data = NULL;
    unsigned int digest_len;
    int ext_data_len;
    ASN1_OCTET_STRING *keyid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();

    X509_pubkey_digest(cert, EVP_sha1(), digest, &digest_len);
    ASN1_OCTET_STRING_set(keyid, digest, (int) digest_len);
    ext_data_len = i2d_ASN1_OCTET_STRING(keyid, &ext_data);

    ASN1_OCTET_STRING_set(octet_string, ext_data, ext_data_len);
    X509_EXTENSION_create_by_NID(&ext, NID_subject_key_identifier, 0, octet_string);

    return 0;
}

int ext_authority_keyid_new(X509_EXTENSION *ext, const X509 *issuer_cert)
{
    if (ext == NULL || issuer_cert == NULL) {
        return -ERROBJNULL;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char *ext_data = NULL;
    unsigned int digest_len;
    int ext_data_len;

    // Create keyid OCTET string
    ASN1_OCTET_STRING *keyid = ASN1_OCTET_STRING_new();
    X509_pubkey_digest(issuer_cert, EVP_sha1(), digest, &digest_len);
    ASN1_OCTET_STRING_set(keyid, digest, (int) digest_len);

    AUTHORITY_KEYID *auth_keyid = AUTHORITY_KEYID_new();
    auth_keyid->keyid = keyid;
    //auth_keyid->serial = ASN1_INTEGER_dup(X509_get_serialNumber(issuer_cert));

    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
    ext_data_len = i2d_AUTHORITY_KEYID(auth_keyid, &ext_data);
    ASN1_OCTET_STRING_set(octet_string, ext_data, ext_data_len);

    X509_EXTENSION_create_by_NID(&ext, NID_authority_key_identifier, 0, octet_string);

    return 0;
}

int ext_basic_constraints_new(X509_EXTENSION *ext, int is_ca, int path_length)
{
    if (ext == NULL) {
        return -ERROBJNULL;
    }

    BASIC_CONSTRAINTS *basic_constraints = BASIC_CONSTRAINTS_new();
    if (is_ca >= 1) {
        is_ca = 1;
    } else {
        is_ca = 0;
    }
    if (path_length > 0) {
        ASN1_INTEGER *len = ASN1_INTEGER_new();
        ASN1_INTEGER_set_int64(len, path_length);
        basic_constraints->pathlen = len;
    }
    basic_constraints->ca = is_ca;

    unsigned char *ext_data = NULL;
    int ext_data_len;
    ext_data_len = i2d_BASIC_CONSTRAINTS(basic_constraints, &ext_data);
    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet_string, ext_data, ext_data_len);

    X509_EXTENSION_create_by_NID(&ext, NID_basic_constraints, 1, octet_string);

    return 0;
}

int ext_key_usage_new(X509_EXTENSION *ext)
{
    if (ext == NULL) {
        return -ERROBJNULL;
    }
    unsigned char *ext_data = NULL;
    int ext_data_len;
    ASN1_BIT_STRING *bit_string = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set_bit(bit_string, 0, KU_KEY_CERT_SIGN);
    ASN1_BIT_STRING_set_bit(bit_string, 1, KU_CRL_SIGN);
    ASN1_BIT_STRING_set_bit(bit_string, 2, KU_DIGITAL_SIGNATURE);

    ext_data_len = i2d_ASN1_BIT_STRING(bit_string, &ext_data);

    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet_string, ext_data, ext_data_len);

    X509_EXTENSION_create_by_NID(&ext, NID_key_usage, 1, octet_string);

    return 0;
}

int authority_information_access_add_item_uri(AUTHORITY_INFO_ACCESS *aia, int obj_nid, const char *uri)
{
    if (aia == NULL || uri == NULL) {
        return -ERROBJNULL;
    }

    ASN1_OBJECT *obj = OBJ_nid2obj(obj_nid);
    GENERAL_NAME *name = GENERAL_NAME_new();
    name->type = GEN_URI;
    name->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
    ASN1_STRING_set(name->d.uniformResourceIdentifier, uri, (int) strlen(uri));

    ACCESS_DESCRIPTION *ad = ACCESS_DESCRIPTION_new();
    ad->method = obj;
    ad->location = name;

    sk_ACCESS_DESCRIPTION_push(aia, ad);

    OBJ_cleanup();
    return 0;
}

int ext_authority_info_access_new(X509_EXTENSION *ext, AUTHORITY_INFO_ACCESS *aia)
{
    if (ext == NULL || aia == NULL) {
        return -ERROBJNULL;
    }
    unsigned char *ext_data = NULL;
    int ext_data_len;

    ext_data_len = i2d_AUTHORITY_INFO_ACCESS(aia, &ext_data);

    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet_string, ext_data, ext_data_len);

    X509_EXTENSION_create_by_NID(&ext, NID_info_access, 0, octet_string);

    ASN1_OCTET_STRING_free(octet_string);
    OBJ_cleanup();
    return 0;
}

int crl_dist_point_add_item_uri(CRL_DIST_POINTS *cdp, const char *uri)
{
    if (cdp == NULL) {
        return -ERROBJNULL;
    }

    GENERAL_NAME *general_name = GENERAL_NAME_new();
    general_name->type = GEN_URI;
    general_name->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
    ASN1_STRING_set(general_name->d.uniformResourceIdentifier, uri, (int) strlen(uri));

    DIST_POINT *dp = DIST_POINT_new();
    dp->distpoint = DIST_POINT_NAME_new();
    DIST_POINT_NAME *dp_name = DIST_POINT_NAME_new();
    dp_name->type = 0; // Full name
    dp_name->name.fullname = GENERAL_NAMES_new();
    sk_GENERAL_NAME_push(dp_name->name.fullname, general_name);
    dp->distpoint = dp_name;

    sk_DIST_POINT_push(cdp, dp);

    return 0;
}

int ext_crl_dist_point_new(X509_EXTENSION *ext, CRL_DIST_POINTS *cdp)
{
    if (ext == NULL) {
        return -ERROBJNULL;
    }
    unsigned char *ext_data = NULL;
    int ext_data_len;

    ext_data_len = i2d_CRL_DIST_POINTS(cdp, &ext_data);

    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet_string, ext_data, ext_data_len);

    X509_EXTENSION_create_by_NID(&ext, NID_crl_distribution_points, 0, octet_string);

    ASN1_OCTET_STRING_free(octet_string);
    return 0;
}

int usernotice_new_text(USERNOTICE *notice, const char *text)
{
    if (notice == NULL || text == NULL) {
        return -ERROBJNULL;
    }

    notice->exptext = ASN1_STRING_new();
    ASN1_STRING_set(notice->exptext, text, (int) strlen(text));

    return 0;
}

#if 0
int usernotice_new_ref(USERNOTICE *notice, const char *ref_url)
{
    if (notice == NULL || ref_url == NULL) {
        return -ERROBJNULL;
    }

    notice->noticeref = NOTICEREF_new();
    notice->noticeref->organization = ASN1_STRING_new();
    notice->noticeref->noticenos = sk_ASN1_INTEGER_new_null();
}
#endif

int policyqualinfo_add_cpsuri(POLICYQUALINFO *qual_info, const char *uri)
{
    if (qual_info == NULL || uri == NULL) {
        return -ERROBJNULL;
    }

    qual_info->pqualid = OBJ_nid2obj(NID_id_qt_cps);
    qual_info->d.cpsuri = ASN1_IA5STRING_new();

    ASN1_STRING_set(qual_info->d.cpsuri, uri, (int) strlen(uri));

    OBJ_cleanup();
    return 0;
}

int policyqualinfo_add_usernotice(POLICYQUALINFO *qual_info, USERNOTICE *notice)
{
    if (qual_info == NULL || notice == NULL) {
        return -ERROBJNULL;
    }

    qual_info->pqualid = OBJ_nid2obj(NID_id_qt_unotice);
    qual_info->d.usernotice = USERNOTICE_new();

    OBJ_cleanup();
    return 0;
}

int certpolicies_add_item(CERTIFICATEPOLICIES *policies, POLICYQUALINFO *qual_info, const char *policy_oid)
{
    if (policies == NULL || qual_info == NULL || policy_oid == NULL) {
        return -ERROBJNULL;
    }
    if (!strcmp(policy_oid, "")) {
        return -ERRSTRNULL;
    }

    POLICYINFO *info = POLICYINFO_new();
    info->policyid = ASN1_OBJECT_new();
    info->qualifiers = sk_POLICYQUALINFO_new_null();

    info->policyid = OBJ_txt2obj(policy_oid, 0);

    sk_POLICYQUALINFO_push(info->qualifiers, qual_info);
    sk_POLICYINFO_push(policies, info);

    OBJ_cleanup();
    return 0;
}

int ext_cert_policy_new(X509_EXTENSION *ext, CERTIFICATEPOLICIES *policies)
{
    if (ext == NULL || policies == NULL) {
        return -ERROBJNULL;
    }
    unsigned char *ext_data = NULL;
    int ext_data_len;

    ext_data_len = i2d_CERTIFICATEPOLICIES(policies, &ext_data);

    ASN1_OCTET_STRING *octet_string = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet_string, ext_data, ext_data_len);

    X509_EXTENSION_create_by_NID(&ext, NID_certificate_policies, 0, octet_string);

    return 0;
}