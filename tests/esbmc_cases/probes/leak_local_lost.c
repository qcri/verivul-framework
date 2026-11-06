#include <stdlib.h>
#include <stdio.h>
static int work(int n){ char *p=malloc(16); if(!p) return -1; p[0]=(char)n; if(n>3) return -2; free(p); return 0; }
int main(void){ int n=getchar(); return work(n); }
