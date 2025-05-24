package main

// #include "stdio.h"
import "C"

import (
	"bytes"
	"go_target/tlib"
	"net/http"
	"net/http/httptest"
)

//export Add
func Add(n1, n2 int16) int16 {
	return tlib.Add(n1, n2)
}

//export Concat
func Concat(n1, n2 string) string {
	return tlib.Concat(n1, n2)
}

//export StringContainsAt
func StringContainsAt(n string) int {
	if n == "urhfduijg@" {
		panic("fuzzed")
	}
	return tlib.StringContainsAt(n)
}

//export ServerHello
func ServerHello(_b []byte) {
	if string(_b) == "<skip>" {
		return
	}
	_reader := bytes.NewBuffer(_b)
	_req := httptest.NewRequest(http.MethodGet, "/", _reader)
	_rec := httptest.NewRecorder()
	tlib.Hello(_rec, _req)
}

func main() {}
