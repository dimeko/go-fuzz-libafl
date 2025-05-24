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
  if(size == -1) {
    return 0;
  }
  // _GoString_ gstring = { data, size };

  // int idx = StringContainsAt(gstring);
  GoSlice _goBuff = {data, size, 5000};
  ServerHello(_goBuff);

  // if(idx != -1) {
  //   abort();

  // } else {
    return 0;
  // }
}

int main() {
  // _GoString_ gstring = { "hello", 5 };
  // int idx = StringContainsAt(gstring);
  char *_gotmpBuff = "<skip>";
  GoSlice _goBuf = {_gotmpBuff, 6, 6};

  ServerHello(_goBuf);
  // // printf("res: %d\n", res);
  uint8_t buf[10] = {0};
  LLVMFuzzerTestOneInput(buf, -1);
  return 0;
}