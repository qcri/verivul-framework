#include <stdlib.h>
#include <stdio.h>
int main(void){ char*p=malloc(16); int c=getchar(); if(c=='q'){ fprintf(stderr,"bye\n"); exit(1);} p[0]=1; free(p); return 0; }
