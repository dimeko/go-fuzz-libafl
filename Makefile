.PHONY: clean build_harness build_fuzzer run

build_harness:
	go build -C go_lib -o bin/libtlib.so -buildmode=c-shared main.go
	cc -g ./harness.c -o harness/harness -L./go_lib/bin -ltlib \
    -Wl,-rpath='./go_lib/bin' && chmod +x harness/harness && ./harness/harness

build_fuzzer:
	cargo build	\
		--profile dev \
		--target-dir ./target

run: build_harness build_fuzzer
	./target/debug/go_lib \
        --coverage-path ./target/cov.drcov \
        --input-dir ./corpus \
        --verbose \
		-- harness/harness

clean:
	cargo clean

