#include <stdlib.h>
int main(void) { char *p = malloc(16); if (!p) return 1; p[0] = 1; return p[0]; }
