#include <stdlib.h>
#include <stdio.h>
int main(void){ char*p=malloc(16); int c=getchar(); if(c=='q') abort(); p[0]=1; free(p); return 0; }
