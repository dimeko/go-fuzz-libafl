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

Benchmarks:
- CalibrationStage::new(&calibration_feedback), tracing, i2s, power); first solution for "\_!_!" found after  2m-56s and executions: 15864
- CalibrationStage::new(&calibration_feedback)); first solution for "\_!_!" found after (approx) 2m 6s and executions: 12800
- CalibrationStage::new(&calibration_feedback)); and without CmpLogChildModule qemu modules solution for "\_!_!" not found after 6 minutes
