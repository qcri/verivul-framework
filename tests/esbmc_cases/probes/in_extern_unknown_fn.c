int parse_ext(unsigned char *buf, int n);
int main(void){ unsigned char b[16]; int t[4]={0}; int k=parse_ext(b,16); if(k<0) return 1; t[k]=1; return t[0]; }
