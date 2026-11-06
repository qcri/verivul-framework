#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
struct hdr { uint16_t len; };
static size_t body_len(const struct hdr *h) { return h->len; }
static void copy_body(char *dst, size_t cap, const char *src, size_t n) { if (n <= cap) memcpy(dst, src, n); }
static void handle(const char *buf, size_t n) {
    struct hdr h; h.len = (uint16_t)n;   /* truncation: n > 65535 wraps */
    char out[128];
    copy_body(out, sizeof out - 1, buf, n > 127 ? 127 : n);
    size_t bl = body_len(&h);
    if (bl < sizeof out) out[bl] = 0;    /* fine */
    (void)out;
}
int main(void) {
    char buf[256]; size_t n = fread(buf, 1, sizeof buf, stdin);
    handle(buf, n);
    return 0;
}
