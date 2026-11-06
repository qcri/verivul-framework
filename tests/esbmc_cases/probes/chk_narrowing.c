#include <stdio.h>
#include <stdint.h>
#include <string.h>
int main(void){ size_t n; if(scanf("%zu",&n)!=1) return 1; uint16_t len=(uint16_t)n; char b[70000]; if(n<sizeof b){ memset(b,0,n); } printf("%u\n",len); return 0; }
