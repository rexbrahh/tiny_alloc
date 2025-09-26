// test.c
#include "tiny_alloc.c" // for a quick test; normally build as a separate object
#include <stdio.h>

int main() {
  void *a = tiny_malloc(24);
  void *b = tiny_malloc(1000);
  a = tiny_realloc(a, 200);
  tiny_free(b);
  void *c = tiny_malloc(500);
  tiny_free(a);
  tiny_free(c);
  puts("OK");
}
