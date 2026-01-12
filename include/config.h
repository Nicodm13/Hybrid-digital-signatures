#ifndef CONFIG_H
#define CONFIG_H

#include "scheme.h"

/* Hybrid Scheme selection */
#define HYBRID_SCHEME ((scheme_t)SCHEME_ECDSA_ML_DSA)

/* Upload endpoint */
#define UPLOAD_URL "http://10.133.252.198:8000"

/* Server-side storage */
#define SERVER_STORAGE_PATH "./"
#define SERVER_STORAGE_NAME "test_signed.bin"

#endif
