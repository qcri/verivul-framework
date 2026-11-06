#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
    if (argc < 3) { fprintf(stderr, "usage\n"); return 1; }
    int n = atoi(argv[1]);
    size_t l = strlen(argv[2]);
    printf("%d %zu\n", n, l);
    return 0;
}
