#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "config.h"
#include "hybrid_signature.h"

int upload_signed_image(const uint8_t *image, size_t image_len, const hybrid_signature_t *sig, const uint8_t *pubkeys, size_t pubkeys_len)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    uint32_t img_len_u32 = (uint32_t)image_len;
    uint32_t sig_len_u32 = (uint32_t)(sizeof(*sig) + sig->len);
    uint32_t pk_len_u32  = (uint32_t)pubkeys_len;

    size_t header_len = 12;
    size_t total_len =
        header_len +
        image_len +
        sig_len_u32 +
        pubkeys_len;

    uint8_t *payload = malloc(total_len);
    if (!payload) {
        curl_easy_cleanup(curl);
        return -1;
    }

    uint8_t *p = payload;

    memcpy(p, &img_len_u32, 4); p += 4;
    memcpy(p, &sig_len_u32, 4); p += 4;
    memcpy(p, &pk_len_u32,  4); p += 4;

    memcpy(p, image, image_len); p += image_len;
    memcpy(p, sig, sig_len_u32); p += sig_len_u32;
    memcpy(p, pubkeys, pubkeys_len);

    curl_easy_setopt(curl, CURLOPT_URL, UPLOAD_URL);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, total_len);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    free(payload);

    return (res == CURLE_OK) ? 0 : -1;
}
