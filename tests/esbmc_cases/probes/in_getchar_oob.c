#include <stdio.h>
int main(void){ char buf[16]; int i=0,c; while((c=getchar())!=EOF && c!='\n'){ buf[i++]=(char)c; } buf[i]=0; return buf[0]; }
