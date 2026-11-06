#include <stdio.h>
int main(void){ unsigned char buf[64]; FILE*f=fopen("cfg.bin","rb"); if(!f) return 1; size_t n=fread(buf,1,sizeof buf,f); return (int)n; }
