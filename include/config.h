#ifndef CONFIG_H
#define CONFIG_H

#include "scheme.h"

/* Hybrid Scheme selection */
#define HYBRID_SCHEME ((scheme_t)SCHEME_ECDSA_ML_DSA)

/* Image settings */
#define IMAGE_INPUT_PATH "../"
#define IMAGE_INPUT_NAME "test.png"

/* Upload endpoint */
#define UPLOAD_URL "http://127.0.0.1:8000"

/* Server-side storage */
#define SERVER_STORAGE_PATH "./"
#define SERVER_STORAGE_NAME "test_signed.bin"

#endif
