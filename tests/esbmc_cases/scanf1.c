#include <stdio.h>
int main(void) {
    unsigned int x;
    if (scanf("%u", &x) != 1) return 1;
    printf("%u\n", x);
    return 0;
}
