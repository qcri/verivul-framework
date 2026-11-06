#include <stdio.h>
#include <string.h>
int main(void) {
    char line[64]; char out[16];
    if (!fgets(line, sizeof line, stdin)) return 1;
    size_t n = strlen(line);
    if (n > 15) n = 15;
    memcpy(out, line, n); out[n] = 0;
    return out[0];
}
