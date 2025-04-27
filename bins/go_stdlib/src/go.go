package main

import (
	"go/ast"
	"go/build"
	"go/doc"
	"go/format"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"go/types"
)

func main() {
	var _ = ast.Bad
	var _ = build.AllowBinary
	var _ = doc.AllMethods
	var _ = format.Node
	var _ = importer.Default
	var _ = parser.AllErrors
	var _ = printer.RawFormat
	var _ = scanner.ScanComments
	var _ = token.ADD
	var _ = types.Bool
}
