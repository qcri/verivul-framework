void fill_ext(unsigned char *buf, int n);
int main(void){ unsigned char b[16]={0}; int t[4]={0}; fill_ext(b,16); unsigned i=b[0]; t[i]=1; return t[0]; }
