#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    int n = atoi(argv[1]);
    printf("%d\n", n);
    assert(0);
    return 0;
}
