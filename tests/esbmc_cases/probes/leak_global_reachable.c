#include <stdlib.h>
static char *g; int main(void){ g=malloc(16); g[0]=1; return g[0]; }
