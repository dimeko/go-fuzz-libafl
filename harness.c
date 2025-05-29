#include "go_app/bin/libtlib.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  if(size == -1) {
    return 0;
  }

  GoSlice _goBuff = {data, size, 5000};
  GoInt8 res = ServerHello(_goBuff);

  return (int)res;
}

int main() {

  char *_gotmpBuff = "<skip>";
  GoSlice _goBuf = {_gotmpBuff, 6, 6};

  ServerHello(_goBuf);
  // // printf("res: %d\n", res);
  uint8_t buf[10] = {0};
  LLVMFuzzerTestOneInput(buf, -1);
  return 0;
}