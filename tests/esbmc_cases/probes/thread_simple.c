#include <pthread.h>
#include <stdio.h>
static int counter; static pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER;
static void*w(void*a){ for(int i=0;i<3;i++){ pthread_mutex_lock(&m); counter++; pthread_mutex_unlock(&m);} return a; }
int main(void){ pthread_t t[2]; for(int i=0;i<2;i++) pthread_create(&t[i],0,w,0); for(int i=0;i<2;i++) pthread_join(t[i],0); printf("%d\n",counter); return 0; }
