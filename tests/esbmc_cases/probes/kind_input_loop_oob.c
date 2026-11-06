#include <stdio.h>
int main(void){ int b[256]; unsigned n; if(scanf("%u",&n)!=1) return 1; if(n>1000) n=1000; for(unsigned i=0;i<n;i++) b[i]=(int)i; return n?b[0]:0; }
