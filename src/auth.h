#ifndef TINYPROXY_AUTH_H
#define TINYPROXY_AUTH_H

#include "hashmap.h"

extern int insert_auth (char *auth, hashmap_t * auth_table);

extern int check_auth (hashmap_t headers, hashmap_t auth_table);

#endif
