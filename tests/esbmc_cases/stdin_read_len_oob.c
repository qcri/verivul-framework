#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
struct pkt { uint8_t len; uint8_t data[32]; };
static int parse(struct pkt *p, const uint8_t *buf, size_t n) {
    if (n < 1) return -1;
    p->len = buf[0];
    if (p->len > n - 1) return -1;
    memcpy(p->data, buf + 1, p->len);   /* len up to 255 but data is 32: overflow */
    return 0;
}
int main(void) {
    uint8_t buf[64]; struct pkt p;
    size_t n = fread(buf, 1, sizeof buf, stdin);
    if (parse(&p, buf, n) != 0) return 1;
    return p.data[0];
}
