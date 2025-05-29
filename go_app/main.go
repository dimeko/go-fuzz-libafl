package main

// #include "stdio.h"
import "C"

import (
	"bytes"
	"go_target/tlib"
	"net/http"
	"net/http/httptest"
)

// //export Add
// func Add(n1, n2 int16) int16 {
// 	return tlib.Add(n1, n2)
// }

// //export Concat
// func Concat(n1, n2 string) string {
// 	return tlib.Concat(n1, n2)
// }

// //export StringContainsAt
// func StringContainsAt(n string) int {
// 	if n == "urhfduijg@" {
// 		panic("fuzzed")
// 	}
// 	return tlib.StringContainsAt(n)
// }

//export ServerHello
func ServerHello(_b []byte) int8 {
	if string(_b) == "<skip>" {
		return 0
	}

	_reader := bytes.NewBuffer(_b)
	_req := httptest.NewRequest(http.MethodGet, "/", _reader)
	_res := httptest.NewRecorder()
	tlib.FuzzMeController(_res, _req)

	return 0
}

func main() {}
