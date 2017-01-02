#include "hashmap.h"
#include "auth.h"
#include "log.h"

#define AUTH_BUCKETS 256

/**
 * If the authorization table has not been set up, create it.
 */
static int init_auth_table (hashmap_t * auth_table)
{
        if (!*auth_table) {
                *auth_table = hashmap_create (AUTH_BUCKETS);
                if (!*auth_table) {
                        log_message (LOG_ERR,
                                     "Unable to allocate memory for authorization table");
                        return -1;
                }
        }

        return 0;
}

/*
 * Inserts a new username/password pair into the hashmap. This function
 * will extract username and password from auth. Currently, username and
 * password are both plain text and should be separated by a colon.
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise.
 */
int insert_auth (char *auth, hashmap_t * auth_table)
{
        int password_len, ret;
        char *p, *username, *password;

        assert (auth != NULL);

        ret = init_auth_table (auth_table);
        if (ret != 0) {
                return -1;
        }

        /*
         * Split auth into username/password pair.
         */
        p = strchr (auth, ':');
        if (p == NULL) {
                return -1;
        }

        *p = '\0';
        username = auth;
        password = p + 1;

        password_len = strlen (password);
        if (password_len == 0) {
                return -1;
        }

        /*
         * Store username/password pair into auth_table.
         */
        ret = hashmap_insert (*auth_table, username, password, password_len);
        return ret;
}

/*
 * Checks whether a connection is allowed.
 *
 * Returns:
 *     1 if allowed
 *     0 if denied
 */
int check_auth (hashmap_t headers, hashmap_t auth_table)
{
        return 0;
}
