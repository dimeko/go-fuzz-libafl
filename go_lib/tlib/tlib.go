package tlib

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func Add(n1, n2 int16) int16 {
	return n1 + n2
}

func Concat(n1, n2 string) string {
	return n1 + n2
}

func StringContainsAt(n string) int {
	res := strings.Index(n, "1_1_")
	// fmt.Println("res: ", res)
	// if res != -1 {
	// 	panic("sdkjh")
	// }
	return res
}

type TestInput1 struct {
	Field1 string `json:"field_1"`
	Field2 struct {
		Nest1 string `json:"nest_1"`
		Nest2 string `json:"nest_2"`
	} `json:"field_2"`
	Field3 []string `json:"field_3"`
}

type TestInput2 struct {
	F []string `json:"f"`
}

func Hello(w http.ResponseWriter, req *http.Request) {
	var _req TestInput1
	// body2, _ := ioutil.ReadAll(req.Body)
	// fmt.Printf("bytes: %b", body2)

	_dec := json.NewDecoder(req.Body)
	err := _dec.Decode(&_req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _req.Field1 == "__!!__!!__" {
		panic("fuzzed")
	}

	fmt.Fprintf(w, "Person: %+v", _req)
}

func Headers(w http.ResponseWriter, req *http.Request) {
	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}
