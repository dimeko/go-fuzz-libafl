package tlib

import (
	"fmt"
	"strings"
)

func Add(n1, n2 int16) int16 {
	return n1 + n2
}

func Concat(n1, n2 string) string {
	return n1 + n2
}

func StringContainsAt(n string) int {
	res := strings.Index(n, "@a@@@@@@@@@@i@@@@@@")
	fmt.Println("res: ", res)
	// if res != -1 {
	// 	panic("sdkjh")
	// }
	return res
}
