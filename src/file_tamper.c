#include <stdio.h>

int main(void) {
    FILE *f = fopen("test_signed.bin", "r+b");
    fseek(f, 30, SEEK_SET);   /* choose offset */
    fputc(0xFF, f);
    fclose(f);
    return 0;
}
