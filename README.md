### Fuzz go library

Build harness statically :
```bash
clang-18 -o harness harness.c target/bin/tlib.so && chmod +x harness && ./harness 
```

or build with extern symbols
```bash
# first remove the #include "tlib.h" and add extern int Add(int n1, int n2) __attribute__((weak));
clang-18 -o harness -c  harness.c
clang-18 harness -o main -Wl,--unresolved-symbols=ignore-in-shared-libs
LD_PRELOAD=./target/bin/tlib.so  ./main
```

NOTES:
- See that here we compile statically, a single binary is a generated.
- Compiling the harness with `clang` did not work. When I switched to `cc` it worked. WTF!