#include <unistd.h>
int main(void){ unsigned char buf[64]; int t[8]={0}; ssize_t n=read(0,buf,sizeof buf); if(n<1) return 1; unsigned idx=buf[0]; t[idx]=1; return t[0]; }
