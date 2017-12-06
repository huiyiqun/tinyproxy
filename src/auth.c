#include "hashmap.h"
#include "auth.h"
#include "log.h"
#include "coding.h"

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
        char *key;
        char *val;
        char *sep;
        char *credential;
        unsigned char *plain_credential;
        char *username, *password;
        ssize_t length;
        hashmap_iter result_iter;
        int success = 0;  /* We don't anticipate successful auth, start with failed state */

        /*
         * If there is no auth table allow everything.
         */
        if (!auth_table) {
                return 1;
        }

        result_iter = hashmap_find (headers, "Proxy-Authorization");
        /*
         * No Proxy-Authorization header
         */
        if (hashmap_is_end (headers, result_iter)) {
                return 0;
        }

        length = hashmap_return_entry (headers, result_iter,
                                       &key, (void **) &val);
        if (length < 0) {
                return 0;
        }
        val[length] = 0;  /* value is not NULL terminated */

        sep = strchr(val, ' ');
        /*
         * Invalid Proxy-Authorization header
         */
        if (sep == NULL) {
                return 0;
        }

        /*
         * Currently only Basic is supported
         */
        if (strncmp(val, "Basic", sep - val) != 0) {
                return 0;
        }

        credential = sep + 1;

#ifndef NDEBUG
        fprintf (stderr, "{credential: %s}\n", credential);
#endif

        /* This call allocates a memory buffer, after this we
         * need to free plain_credential before exiting -> goto exit;
         */
        if( (length = base64_decode(credential, &plain_credential)) < 1) {
                goto exit;
        }

#ifndef NDEBUG
        fprintf (stderr, "{plain credential: '%s'}\n", plain_credential);
#endif

        sep = strchr((char *)plain_credential, ':');
        /*
         * No ':' in credential
         */
        if (sep == NULL) {
                goto exit;
        }
        *sep = '\0';

        username = (char *) plain_credential;
        password = sep + 1;

#ifndef NDEBUG
        fprintf (stderr, "Username: '%s'    Password: '%s'\n", username, password);
#endif

        result_iter = hashmap_find (auth_table, username);
        /*
         * No such user
         */
        if (hashmap_is_end (auth_table, result_iter)) {
                goto exit;
        }
        length = hashmap_return_entry (auth_table, result_iter,
                                               &key, (void **) &val);
        if (length < 0) {
                goto exit;
        }
        val[length] = 0;  /* value is not NULL terminated */

        /*
         * Wrong password
         */
        if (strcmp(val, password) != 0) {
                goto exit;
        }

        /* If we arrived here, authentication was successful */
        success = 1;

 exit:
        free(plain_credential);
        return success;
}
