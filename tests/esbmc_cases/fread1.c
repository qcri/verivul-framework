#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint32_t hdr;
    FILE *f = fopen("x.bin", "rb");
    if (!f) return 1;
    if (fread(&hdr, sizeof(uint32_t), 1, f) != 1) { fclose(f); return 1; }
    fclose(f);
    printf("%u\n", hdr);
    return 0;
}
