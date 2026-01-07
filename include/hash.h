#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_LEN 32

void sha256(const uint8_t *msg, size_t len, uint8_t out[HASH_LEN]);

#endif
