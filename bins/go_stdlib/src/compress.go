package main

import (
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
)

func main() {
	var _ = bzip2.StructuralError("bello")
	var _ = flate.BestCompression
	var _ = gzip.BestCompression
	var _ = lzw.LSB
	var _ = zlib.BestCompression
}
