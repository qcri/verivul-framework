#include <stdlib.h>
#include <string.h>
int main(void){ int*a=calloc(4,sizeof(int)); a[0]=1; char*s=strdup("abc"); s[0]='x'; free(a); free(s); return 0; }
