package main

// #include "stdio.h"
import "C"

import (
	"bytes"
	"go_target/tlib"
	"net/http"
	"net/http/httptest"
)

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
