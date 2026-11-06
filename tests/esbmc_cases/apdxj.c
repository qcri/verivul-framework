#include <stdlib.h>
#include <string.h>
static void safe_memcpy(char *dest, const char *src, size_t n) {
    while (n--) { *dest++ = *src++; }
}
int main(void) {
    char src[8] = "abc";
    char dst[8];
    safe_memcpy(dst, src, 0);
    return dst[0];
}
