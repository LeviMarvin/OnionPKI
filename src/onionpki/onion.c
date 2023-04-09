/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#include <stdio.h>
#include <openssl/pem.h>
#include "onionpki/cert.h"
#include "onionpki/key.h"
#include "onionpki/crl.h"
#include "onionpki/storage/dao.h"
#include <sqlite/sqlite3.h>
#include <onionpki/stdonion.h>

#ifdef  __cplusplus
extern "C" {
#endif
#include <openssl/applink.c>
#ifdef  __cplusplus
}
#endif

int main(int argc, char *argv[]) {
#if 0
    if (argc == 1) {
        printf("Please use command help for details.\n");
    } else if (argc == 2) {
        if (!strcmp(argv[1], "version")) {
            printf("OnionPKI version %s\n", onion_version());
            printf("%s\n", OpenSSL_version(OPENSSL_VERSION));
            printf("SQLite: %s\n", sqlite3_version);
        } else if (!strcmp(argv[1], "cert")) {

        } else if (!strcmp(argv[1], "da")) {}
    }
#endif
    sqlite3 *db;
    sqlite3_open("sqlite3.db", &db);
    char *saved = dao_get_text(db, "TBL_CERT", "cert_name", "test", "AD");
    sqlite3_close(db);
    printf("%s", saved);
    return 0;
}
