#include <stdio.h>
#include <string.h>
struct cfg { int port; char host[32]; int flags; };
static void init(struct cfg *c){ c->port=80; strcpy(c->host,"localhost"); }
int main(void){ struct cfg c; init(&c); printf("%d %s\n", c.port, c.host); return 0; }
