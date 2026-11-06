#include <stdlib.h>
#include <stdint.h>
struct node { uint8_t tag; uint32_t v; struct node *next; };
int main(void) {
    struct node *n = malloc(sizeof *n);
    n->tag = 1; n->v = 7; n->next = NULL;
    uint32_t r = n->v;
    free(n);
    return (int)r;
}
