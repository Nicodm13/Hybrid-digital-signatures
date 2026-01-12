#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "hybrid_signature.h"

int upload_signed_image(const uint8_t *image, size_t image_len, const hybrid_signature_t *sig)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    size_t total_len = image_len + sizeof(*sig);
    uint8_t *payload = malloc(total_len);

    memcpy(payload, image, image_len);
    memcpy(payload + image_len, sig, sizeof(*sig));

    curl_easy_setopt(curl, CURLOPT_URL, UPLOAD_URL);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, total_len);

    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    free(payload);

    return (res == CURLE_OK) ? 0 : -1;
}
