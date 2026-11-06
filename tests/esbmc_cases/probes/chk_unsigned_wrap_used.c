#include <stdio.h>
#include <string.h>
int main(void){ char src[64]={0}; char dst[64]; unsigned n; if(scanf("%u",&n)!=1) return 1; if(n>64) return 1; size_t k=n-1; memcpy(dst,src,k); return dst[0]; }
