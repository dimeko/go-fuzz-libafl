### Fuzz Go with [LibAFL](https://github.com/AFLplusplus/LibAFL)

This is a project to get you started with fuzzing Go server controllers. The fuzzing test setup is very similar to how fuzz tests work in Go. Create a request with `httptest`, run the controller and record its response. 
You will also find the `harness.c`, which is ran by the fuzzer, and `main.go` which works as a "sub harness", to help us prepare the environment for Go related stuff (like taking the incoming bytes and placing them all in a single struct field etc).
At the moment, we prefer to run black-box fuzzing and build the target without instrumentation. It would be difficult though, since I do not know any proper way to build instrumentation inside a Go binary.
We run it with Qemu which gives us some modules to observe the runtime like CmpLog.

Build and run :
```bash
make run
```

Notes: 
- In order to run the fuzzer, you have to download [jvob](https://github.com/dimeko/jvob) a small tool to find the json values byte offsets in a json byte vector.
- Sometimes it fails with "No entries in corpus". Simply re-run it
- In `Makefile`, the fuzzer is called with `--offset 600`. 600 is the length of the `FuzzMeController` controller in the the Go library. TODO: find it automatically before start fuzzing.

TODO:
- Improve CmpLog utilization
- Create a wordlist mutator (token mutator)
- Add json values offsets in metadata
- Fix fails on first runs with error "No entries in corpus"
- Improve performance
