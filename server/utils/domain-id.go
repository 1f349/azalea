package utils

import (
	"github.com/julienschmidt/httprouter"
	"strconv"
)

func GetDomainId(params httprouter.Params) int64 {
	n, err := strconv.ParseInt(params.ByName("domain"), 10, 64)
	if err != nil {
		return -1
	}
	return n
}
