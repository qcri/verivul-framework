#include <time.h>
int main(void){ int t[4]={0}; unsigned i=(unsigned)time(NULL)%8; t[i]=1; return t[0]; }
