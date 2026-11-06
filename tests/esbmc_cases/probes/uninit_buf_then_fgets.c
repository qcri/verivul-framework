#include <stdio.h>
#include <string.h>
int main(void){ char line[64]; if(!fgets(line,sizeof line,stdin)) return 1; size_t n=strlen(line); printf("%zu\n",n); return 0; }
