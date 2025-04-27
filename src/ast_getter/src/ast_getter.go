package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

var debug = false

func processNode(fset *token.FileSet, node interface{}, depth int) (string, string, string) {
	package_name := " "
	interface_name := " "
	function_name := " "
	// fmt.Printf("Called with: %v\n", node)
	switch v := node.(type) {
	case *ast.CallExpr:
		node := node.(*ast.CallExpr)
		return processNode(fset, node.Fun, depth+1)

	case *ast.SelectorExpr:
		// SelectorExpr are Dot Operator based calls such t.SizeOf() depending on what t is there can be several cases

		// 1. t.Call() -- t is an interface in which case we need to find the type of t. Sel.Name is the function and X.Obj is t
		// make sure X is an identified
		node := node.(*ast.SelectorExpr)
		function_name = node.Sel.Name
		if debug {
			fmt.Printf("Found selector getting function name from node.Sel.Name %s\n", function_name)
		}
		ident, ok := node.X.(*ast.Ident)
		if ok {
			if node.X.(*ast.Ident).Obj != nil {
				// 1.1 t is a parameter -- field, t is a parameter to the function we are inside
				// grab the object the indentifier represents
				obj := ident.Obj
				// t is a field in which case we can grab the type which in turn is another selector expr i.e. t reflect.Type here
				// we are trying to find the reflect and Type
				decl_type, ok := obj.Decl.(*ast.Field)

				if ok {
					switch decl_type.Type.(type) {
					case *ast.SelectorExpr:
						decl_sel := decl_type.Type.(*ast.SelectorExpr)
						package_name = decl_sel.X.(*ast.Ident).Name
						interface_name = decl_sel.Sel.Name
						if debug {
							fmt.Printf("found selector under selector found package %s and interface %s\n", package_name, interface_name)
						}
					case *ast.Ident:
						file_p := decl_type.Type.(*ast.Ident).NamePos
						file := fset.File(file_p).Name()
						split := strings.Split(file, "/")
						package_name = split[len(split)-2]
						interface_name = decl_type.Type.(*ast.Ident).Name
						if debug {
							fmt.Printf("found ident under selector found package %s and interface %s\n", package_name, interface_name)
						}
					case *ast.StarExpr:
						name := decl_type.Type.(*ast.StarExpr).X.(*ast.Ident).Name
						file_p := decl_type.Type.(*ast.StarExpr).X.(*ast.Ident).NamePos
						file := fset.File(file_p).Name()
						split := strings.Split(file, "/")
						package_name = split[len(split)-2]
						interface_name = name
						if debug {
							fmt.Printf("found star under selector found package %s and function %s\n", package_name, function_name)
						}

					default:
						if debug {
							fmt.Printf("decl_type type is not Selector :( rather %T\n", decl_type.Type)
						}
					}
				} else {
					if debug {
						fmt.Printf("var type is not field :( rather %T\n", obj.Decl)
					}
				}
			} else {
				// 2. package.Call() -- this is a direct call to a package's public function, this should be our concern, maybe we should re-consider this
				package_name = node.X.(*ast.Ident).Name
				if debug {
					fmt.Printf("selector.x.obj is nil updating package name to %s\n", package_name)
				}
			}
		} else {
			if debug {
				fmt.Printf("Selector X is not an ident :( rather %T\n", node.X)
			}
			result_package, result_interface, result_function := processNode(fset, node.X, depth+1)
			if debug {
				fmt.Printf("Result from: %s, %s, %s\n", result_package, result_interface, result_function)
			}
			if interface_name == " " {
				interface_name = result_function
			}
			if package_name == " " {
				package_name = result_package
			}
		}

	case *ast.Ident:
		node := node.(*ast.Ident)
		function_name = node.Name
		if debug {
			fmt.Printf("found ident node updating function name %s\n", function_name)
		}

	default:
		fmt.Printf("Unknow Type: ,, %T!;", v)
		os.Exit(1)
	}
	if depth > 1 {
		return package_name, interface_name, function_name
	}
	fmt.Printf("%v, %v, %v;", package_name, interface_name, function_name)
	return package_name, interface_name, function_name
}

func main() {
	path := flag.String("file", "", "File to create AST for")
	lineNumber := flag.Int("line", 0, "Line to extract Call AST for")
	flag.Parse()
	// Parse the Go source file and get the AST.
	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, *path, nil, parser.ParseComments)
	if err != nil {
		fmt.Println("Error parsing file:", err)
		os.Exit(1)
	}

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && fset.Position(call.Pos()).Line == *lineNumber {
			if debug {
				ast.Print(fset, n)
			}
			processNode(fset, call, 0)
			return true
		}
		return true
	})

	// ast.Inspect(node, func(n ast.Node) bool {
	// 	call, ok := n.(*ast.Ident)
	// 	if ok && fset.Position(call.Pos()).Line == *lineNumber {
	// 		if debug {
	// 			ast.Print(fset, n)
	// 		}
	// 	}
	// 	return true
	// })
	// fmt.Printf("%s,%s,%s", pkg_name, interface_name, function_name)
}
