/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_STDERR_H
#define ONIONPKI_STDERR_H

#define ERRNO 0
#define ERROBJNULL 1
#define ERRSTRNULL 2
#define ERROSSL 3
#define ERROSSL_NID 4
#define ERRSQLITE 5

char *onion_strerror(int err);

#define ALG(name) \
    if (name == "sha1") { \
        return EVP_md_sha1(); \
    } else if (name == "sha256")

#endif //ONIONPKI_STDERR_H
