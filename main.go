package main

import (
	"unsafe"

	"github.com/ItsMonish/barbwire/internal/correlator"
)

func main() {
	println(unsafe.Sizeof(correlator.Event{}))
}
