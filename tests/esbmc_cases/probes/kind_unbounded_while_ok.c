#include <stdio.h>
int main(void){ char line[64]; unsigned long total=0; while(fgets(line,sizeof line,stdin)){ for(int i=0;line[i]&&i<63;i++) total+=(unsigned char)line[i]; } return (int)(total&0xff); }
