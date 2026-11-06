#include <stdlib.h>
int main(void){ char*p=malloc(8); p[0]=1; char*q=realloc(p,32); q[0]=2; free(q); return 0; }
