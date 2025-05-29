.PHONY: clean build_harness build_fuzzer run
GO=go
CARGO=cargo
TARGET=./target/debug/go_lib

build_harness:
	$(GO) build -C go_lib -o bin/libtlib.so -buildmode=c-shared main.go
	cc -g ./harness.c -o harness/harness -L./go_lib/bin -ltlib \
    -Wl,-rpath='./go_lib/bin' && chmod +x harness/harness

build_fuzzer:
	$(CARGO) build	\
		--profile dev \
		--target-dir ./target

run: build_harness build_fuzzer
	$(TARGET) \
        --coverage-path ./target/cov.drcov \
        --input-dir ./corpus \
        --verbose \
		-- harness/harness

clean:
	$(CARGO) clean

