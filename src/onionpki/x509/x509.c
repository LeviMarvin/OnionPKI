/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#include <onionpki/x509/x509.h>

int x509_name_set_data(X509_NAME *name, const char *CN, const char *C, const char *ST, const char *L, const char *O,
                       const char *OU, const char *E, int is_ev, const char *sN, const char *bC, const char *jC,
                       const char *jST, const char *jL)
{
    if (name == NULL || CN == NULL || (
            is_ev && (O == NULL || OU == NULL || C == NULL || ST == NULL || L == NULL ||
            sN == NULL || bC == NULL || jC == NULL || jST == NULL)
            )) {
        return -ERROBJNULL;
    }
    if (!strcmp(CN, "")) {
        return -ERRSTRNULL;
    }

    if (is_ev) {
        if (jL != NULL) {
            X509_NAME_add_entry_by_txt(name, "1.3.6.1.4.1.311.60.2.1.1", MBSTRING_ASC, (const unsigned char *) jL, -1, -1, 0);
        }
        if (jST != NULL) {
            X509_NAME_add_entry_by_txt(name, "1.3.6.1.4.1.311.60.2.1.2", MBSTRING_ASC, (const unsigned char *) jST, -1, -1, 0);
        }
        X509_NAME_add_entry_by_txt(name, "1.3.6.1.4.1.311.60.2.1.3", MBSTRING_ASC, (const unsigned char *) jC, 2, -1, 0);
        X509_NAME_add_entry_by_txt(name, "2.5.4.15", MBSTRING_ASC, (const unsigned char *) bC, -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "2.5.4.5", MBSTRING_ASC, (const unsigned char *) sN, -1, -1, 0);
    }
    if (L != NULL) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char *) L, -1, -1, 0);
    }
    if (E != NULL) {
        X509_NAME_add_entry_by_txt(name, "E", MBSTRING_ASC, (const unsigned char *) E, -1, -1, 0);
    }
    if (ST != NULL) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char *) ST, -1, -1, 0);
    }
    if (C != NULL) {
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *) C, 2, -1, 0);
    }
    if (OU != NULL) {
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char *) OU, -1, -1, 0);
    }
    if (O != NULL) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *) O, -1, -1, 0);
    }
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *) CN, -1, -1, 0);

    return 0;
}

#if 0
int x509_name_set_evdata(
        X509_NAME *name, const char *CN,
        const char *C, const char *ST, const char *L,
        const char *E
)
{
    return 0;

}
#endif