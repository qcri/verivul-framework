#include <stdlib.h>
#include <stdint.h>
struct n{ uint8_t t; uint64_t v; struct n*next; };
int main(void){ struct n*h=NULL; for(int i=0;i<3;i++){ struct n*x=malloc(sizeof*x); x->t=1; x->v=i; x->next=h; h=x; } uint64_t s=0; for(struct n*c=h;c;c=c->next) s+=c->v; while(h){ struct n*nx=h->next; free(h); h=nx; } return (int)s; }
