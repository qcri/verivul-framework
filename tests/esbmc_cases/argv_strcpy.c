#include <string.h>
int main(int argc, char **argv) {
    char b[4];
    if (argc < 2) return 1;
    strcpy(b, argv[1]);
    return b[0];
}
