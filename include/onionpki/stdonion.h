/*
 * Copyright (c) 2023 The OnionPKI Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_STDONION_H
#define ONIONPKI_STDONION_H

#include <openssl/evp.h>

const char *onion_version(void);
const EVP_MD *onion_evp_md_get_by_code(int md);

#endif //ONIONPKI_STDONION_H
