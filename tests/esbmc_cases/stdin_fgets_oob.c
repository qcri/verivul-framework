#include <stdio.h>
#include <string.h>
static void fill(char *dst, const char *src, size_t n) { for (size_t i = 0; i <= n; i++) dst[i] = src[i]; }
int main(void) {
    char line[64]; char out[16];
    if (!fgets(line, sizeof line, stdin)) return 1;
    size_t n = strlen(line);
    if (n > 16) n = 16;
    fill(out, line, n);
    return out[0];
}
