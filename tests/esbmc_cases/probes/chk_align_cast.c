#include <stdint.h>
#include <stdio.h>
int main(void){ unsigned char buf[8]={1,2,3,4,5,6,7,8}; uint32_t v=*(uint32_t*)&buf[2]; printf("%u\n",v); return 0; }
