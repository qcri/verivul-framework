#include <stdio.h>
#include <stdlib.h>
int main(void){ char b[16]; printf("hi\n"); fgets(b,sizeof b,stdin); char*p=malloc(8); p[0]=1; free(p); return 0; }
