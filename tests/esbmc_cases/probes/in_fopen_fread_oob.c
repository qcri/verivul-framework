#include <stdio.h>
int main(void){ unsigned char buf[64]; int t[8]={0}; FILE*f=fopen("cfg.bin","rb"); if(!f) return 1; size_t n=fread(buf,1,sizeof buf,f); fclose(f); if(n<1) return 1; unsigned idx=buf[0]; t[idx]=1; return t[0]; }
