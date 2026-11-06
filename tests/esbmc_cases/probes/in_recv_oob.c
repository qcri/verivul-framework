#include <sys/socket.h>
int main(void){ unsigned char buf[64]; int t[8]={0}; ssize_t n=recv(3,buf,sizeof buf,0); if(n<1) return 1; unsigned idx=buf[0]; t[idx]=1; return t[0]; }
