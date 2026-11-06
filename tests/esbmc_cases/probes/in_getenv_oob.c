#include <stdlib.h>
#include <string.h>
int main(void){ char b[8]; const char*e=getenv("HOME"); if(!e) return 1; strcpy(b,e); return b[0]; }
