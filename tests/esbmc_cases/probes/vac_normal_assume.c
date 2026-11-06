#include <stdio.h>
int main(void){ int x; if(scanf("%d",&x)!=1) return 1; __ESBMC_assume(x>=0 && x<4); int t[4]={0}; t[x]=1; return t[0]; }
