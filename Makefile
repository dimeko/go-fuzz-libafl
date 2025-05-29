.PHONY: clean build_harness build_fuzzer run
CC=cc
GO=go
CARGO=cargo
TARGET=./target/debug/go_libafl_fuzz

build_harness:
	$(GO) build -C go_app -o bin/libtlib.so -buildmode=c-shared main.go
	$(CC) -g ./harness.c -o harness/harness -L./go_app/bin -ltlib \
    	-Wl,-rpath='./go_app/bin' && chmod +x harness/harness

build_fuzzer:
	$(CARGO) build	\
		--profile dev \
		--target-dir ./target

run: build_harness build_fuzzer
	$(TARGET) --verbose -- harness/harness

clean:
	$(CARGO) clean

