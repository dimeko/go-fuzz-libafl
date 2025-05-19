package main

// #include "stdio.h"
import "C"

import (
	"go_target/tlib"
)

//export Add
func Add(n1 , n2 int16) int16 {
	return tlib.Add(n1, n2)
}

//export Concat
func Concat(n1 , n2 string) string {
	if n1 == "fuzzed" {
		panic("fuzzed")
	}
	return tlib.Concat(n1, n2)
}

//export StringContainsAt
func StringContainsAt(n string) int {
	if n == "@@@" {
		panic("fuzzed")
	}
	return tlib.StringContainsAt(n)
}

func main() {}