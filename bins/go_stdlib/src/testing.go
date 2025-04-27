package main

import (
	"testing"
	"testing/iotest"
	"testing/quick"
)

func main() {
	var _ = testing.Init
	var _ = iotest.DataErrReader
	var _ = quick.Check
}
