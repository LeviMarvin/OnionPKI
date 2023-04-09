/*
 * Copyright (c) 2023 The Project Project Authors. All Rights Reserved.
 */

#ifndef ONIONPKI_DAO_H
#define ONIONPKI_DAO_H

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <sqlite/sqlite3.h>
#include <onionpki/stderr.h>

char *dao_get_text(sqlite3 *db, const char *table, const char *column, const char *con_key, const char *con_value);
int dao_get_blobs(sqlite3 *db, const char *table, const char *column, unsigned char **saved, int *saved_len,
                  const char *con_key, const char *con_value);

#endif //ONIONPKI_DAO_H
