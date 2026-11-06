#include <stdint.h>
#include <stdio.h>
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
int main(void) {
    uint8_t b[4] = {200, 1, 2, 3};
    printf("%u\n", be32(b));
    return 0;
}
