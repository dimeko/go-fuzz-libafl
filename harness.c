#include "go_lib/bin/libtlib.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// extern int Add(int n1, int n2) __attribute__((weak));

// int main() {
//     int res = Add(1, 666);
//     printf("res: %d\n", res);
// }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  _GoString_ gstring = { data, size };

  int idx = StringContainsAt(gstring);

  if(idx != -1) {
    abort();

  } else {
    return 0;
  }
}

int main() {
  _GoString_ gstring = { "hello", 5 };
  int idx = StringContainsAt(gstring);
  // printf("res: %d\n", res);
  uint8_t buf[10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);
  return 0;
}