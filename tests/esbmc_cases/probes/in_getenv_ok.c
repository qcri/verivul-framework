#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void){ char b[8]; const char*e=getenv("HOME"); if(!e) return 1; snprintf(b,sizeof b,"%s",e); return b[0]; }
