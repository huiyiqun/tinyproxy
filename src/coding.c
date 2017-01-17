#include "coding.h"
#include <openssl/bio.h>
#include <openssl/evp.h>

int base64_decode(char *b64msg, unsigned char **buffer, size_t *length) {
        BIO *bio, *b64;
        int plain_len;
        int b64_len;
        
        b64_len = strlen(b64msg);

        /*
         * Calculate length of decoded message
         */
        plain_len = (b64_len * 3) / 4;
        if (b64msg[b64_len-1] == '=') {
                plain_len -= 1;
                if (b64msg[b64_len-2] == '=') {
                        plain_len -= 1;
                }
        }

        if (plain_len < 0) {
                return -1;
        }
        (*buffer) = (unsigned char *)malloc(sizeof(unsigned char) * plain_len);
        (*buffer)[plain_len-1] = '\0';

        /*
         * Build BIO chain
         */
        bio = BIO_new_mem_buf(b64msg, -1);
        b64 = BIO_new(BIO_f_base64());
        BIO_push(b64, bio);

        /*
         * Decode
         */
        if (BIO_read(b64, *buffer, plain_len) != plain_len) {
                return -1;
        }

        BIO_free_all(b64);
        return 0;
}
