#include <stdio.h>
int main(void){ int t[8]={0}; int i; if(scanf("%d",&i)!=1) return 1; if(i<0||i>7) return 1; t[i]=1; return t[0]; }
