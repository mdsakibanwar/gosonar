package main

import (
	"html"
	"html/template"
)

func main() {
	var _ = template.ErrBadHTML
	var _ = html.EscapeString
}
