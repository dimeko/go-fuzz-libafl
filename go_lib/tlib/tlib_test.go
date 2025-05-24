package tlib

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func FuzzStringContainsAt(f *testing.F) {
	f.Add(34, "1223")
	f.Fuzz(func(t *testing.T, i int, s string) {
		fmt.Println("test case input: ", s)
		_r := StringContainsAt(s)
		assert.Equal(t, _r, -1, s)
	})
}
