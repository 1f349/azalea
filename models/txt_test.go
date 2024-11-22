package models

import (
	"fmt"
	"strings"
	"testing"
)

func TestSplitTxtValue(t *testing.T) {
	for _, a := range []struct {
		len  int
		end  int
		test int
	}{
		{1, 0, 0},
		{1, 100, 100},
		{1, 200, 200},
		{1, 255, 255},
		{2, 1, 256},
		{3, 90, 600},
	} {
		out := splitTxtValue(strings.Repeat("A", a.test))
		if len(out) == 0 {
			panic("TXT value should not be empty")
		}
		if len(out) != a.len {
			panic(fmt.Sprintf("Invalid TXT value length, expected %d but got %d", a.len, len(out)))
		}
		for i := range len(out) - 1 {
			if len(out[i]) != 255 {
				panic("All values except the last should have a length of 255")
			}
		}
		actualEnd := len(out[len(out)-1])
		if actualEnd != a.end {
			panic(fmt.Sprintf("Last item in TXT value should be %d but is %d", a.end, actualEnd))
		}
	}
}
