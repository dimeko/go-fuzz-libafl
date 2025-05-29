package tlib

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type TestInput1 struct {
	Field1 string `json:"field_1"`
	Field2 struct {
		Nest1 string `json:"nest_1"`
		Nest2 string `json:"nest_2"`
	} `json:"field_2"`
	Field3 []string `json:"field_3"`
}

func FuzzMeController(w http.ResponseWriter, req *http.Request) {
	var _req TestInput1

	_dec := json.NewDecoder(req.Body)
	err := _dec.Decode(&_req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _req.Field1 == "fuzz_me_if_you_can" {
		panic("fuzzed")
	}

	fmt.Fprintf(w, "Hello: %+v", _req)
}
