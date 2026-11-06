#include <assert.h>
int main(void){ int x=3; __ESBMC_assume(x>5); int t[2]={0}; t[7]=1; return t[0]; }
