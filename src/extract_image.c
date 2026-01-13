#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "config.h"

int main(void)
{
    char input_path[512];
    const char *output_path = "image.png";

    /* Build input path from config */
    snprintf(input_path, sizeof(input_path), "%s%s",
             SERVER_STORAGE_PATH,
             SERVER_STORAGE_NAME);

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        perror("fopen input");
        return 1;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror("fopen output");
        fclose(in);
        return 1;
    }

    uint32_t image_len_net;
    if (fread(&image_len_net, sizeof(uint32_t), 1, in) != 1) {
        fprintf(stderr, "Failed to read image length\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    uint32_t image_len = ntohl(image_len_net);

    uint8_t buffer[4096];
    uint32_t remaining = image_len;

    while (remaining > 0) {
        size_t chunk = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;

        size_t r = fread(buffer, 1, chunk, in);
        if (r != chunk) {
            fprintf(stderr, "Unexpected EOF while reading image data\n");
            fclose(in);
            fclose(out);
            return 1;
        }

        fwrite(buffer, 1, r, out);
        remaining -= (uint32_t)r;
    }

    fclose(in);
    fclose(out);

    printf("Extracted PNG from %s to %s (%u bytes)\n",
           input_path, output_path, image_len);

    return 0;
}
