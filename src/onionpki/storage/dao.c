/*
 * Copyright (c) 2023 The Project Project Authors. All Rights Reserved.
 */

#include <onionpki/storage/dao.h>

char *dao_get_text(sqlite3 *db, const char *table, const char *column, const char *con_key, const char *con_value)
{
    if (table == NULL || con_key == NULL || con_value == NULL || column == NULL) {
        return NULL;
    }
    int rc, len;
    char *string_sql;
    char *text;
    const char *cszSql = "SELECT %s FROM %s WHERE %s=?";
    sqlite3_stmt *stmt;

    string_sql = (char *) malloc(sizeof(char) * (
            strlen(cszSql) +
            strlen(column) +
            strlen(table) +
            strlen(con_key)
    ) + 1);
    sprintf(string_sql, cszSql, column, table, con_key);

    rc = sqlite3_prepare_v2(db, string_sql, -1, &stmt, 0);
    free(string_sql);
    if (rc != SQLITE_OK) {
        return NULL;
    }

    rc = sqlite3_bind_text(stmt, 1, con_value, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        return NULL;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        return NULL;
    }

    len = sqlite3_column_bytes(stmt, 0);
    text = (char *) malloc(sizeof(char) * (len + 1));
    memcpy(text, sqlite3_column_text(stmt, 0), len);
    text[len] = '\0';

    sqlite3_reset(stmt);
    sqlite3_finalize(stmt);

    return text;
}

int dao_get_blobs(sqlite3 *db, const char *table, const char *column, unsigned char **saved, int *saved_len,
                  const char *con_key, const char *con_value)
{
    if (db == NULL || table == NULL || column == NULL || saved == NULL) {
        return -ERROBJNULL;
    }
    if (!strcmp(table, "") || !strcmp(column, "")) {
        return -ERRSTRNULL;
    }
    int conditions = 0;
    if ((con_key != NULL && con_value != NULL) && (!strcmp(con_key, "") && !strcmp(con_value, ""))) {
        conditions = 1;
    }
    sqlite3_stmt *stmt;
    const char *basic_string = "SELECT %s FROM %s";
    const char *full_string = "SELECT %s FROM %s WHERE %s='%s'";
    char *query_string;
    if (conditions) {
        query_string = (char *) malloc(sizeof(char) * strlen(full_string) + strlen(column) + strlen(table));
        sprintf(query_string, full_string, column, table, con_key, con_value);
    } else {
        query_string = (char *) malloc(sizeof(char) * strlen(basic_string) + strlen(column) + strlen(table));
        sprintf(query_string, basic_string, column, table);
    }

    if (sqlite3_prepare_v2(db, query_string, -1, &stmt, NULL) != SQLITE_OK) {
        return -ERRSQLITE;
    }
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        return -ERRSQLITE;
    }
    if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB) {
        return -ERRSQLITE;
    }
    *saved_len = sqlite3_column_bytes(stmt, 0);
    *saved = malloc(*saved_len);
    memcpy(*saved, sqlite3_column_blob(stmt, 0), *saved_len);

    sqlite3_finalize(stmt);
    return 0;
}
