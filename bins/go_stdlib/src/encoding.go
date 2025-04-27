package main

import (
	"encoding/ascii85"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
)

func main() {
	var _ = ascii85.Encode
	var _ = asn1.ClassApplication
	var _ = base32.HexEncoding
	var _ = base64.NoPadding
	var _ = binary.MaxVarintLen16
	var _ = csv.NewWriter
	var _ = gob.NewDecoder
	var _ = hex.Decode
	var _ = json.Compact
	var _ = pem.Encode
	var _ = xml.Escape
}
