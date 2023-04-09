/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_EXT_H
#define ONIONPKI_EXT_H

#include <onionpki/x509/x509.h>
#include <onionpki/stderr.h>

int ext_new(X509_EXTENSION *ext, int is_crit, const char *oid,
            struct asn1_string_st *data);
int ext_subject_keyid_new(X509_EXTENSION *ext, X509 *cert);
int ext_authority_keyid_new(X509_EXTENSION *ext, const X509 *issuer_cert);
int ext_basic_constraints_new(X509_EXTENSION *ext, int is_ca, int path_length);
int ext_key_usage_new(X509_EXTENSION *ext);

int authority_information_access_add_item_uri(AUTHORITY_INFO_ACCESS *aia, int obj_nid, const char *uri);
int ext_authority_info_access_new(X509_EXTENSION *ext, AUTHORITY_INFO_ACCESS *aia);

int crl_dist_point_add_item_uri(CRL_DIST_POINTS *cdp, const char *uri);
int ext_crl_dist_point_new(X509_EXTENSION *ext, CRL_DIST_POINTS *cdp);

int policyqualinfo_add_cpsuri(POLICYQUALINFO *qual_info, const char *uri);
int policyqualinfo_add_usernotice(POLICYQUALINFO *qual_info, USERNOTICE *notice);
int certpolicies_add_item(CERTIFICATEPOLICIES *policies, POLICYQUALINFO *qual_info, const char *policy_oid);
int ext_cert_policy_new(X509_EXTENSION *ext, CERTIFICATEPOLICIES *policies);

#endif //ONIONPKI_EXT_H
