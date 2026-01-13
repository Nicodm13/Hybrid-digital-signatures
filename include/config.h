#ifndef CONFIG_H
#define CONFIG_H

#include "scheme.h"

/* Hybrid Scheme selection */
#define HYBRID_SCHEME ((scheme_t)SCHEME_ECDSA_ML_DSA)

/* Server endpoint (WSL) */
#define SERVER_IP "10.133.252.198"
#define SERVER_PORT 8000

/* Server-side storage */
#define SERVER_STORAGE_PATH "./"
#define SERVER_STORAGE_NAME "test_signed.bin"

#endif
