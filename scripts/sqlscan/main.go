// Command sqlscan enforces invariant I4 on the go-p2pmesh source tree:
// SQL must be built with parameter binding, never with fmt.Sprintf or
// string concatenation, and user data must never be interpolated into
// the SQL text itself (which is how an identifier would leak in).
//
// It parses real Go ASTs (go/parser + go/ast) rather than grepping, so a
// comment that mentions fmt.Sprintf is not a false positive.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ruleSQLConcat = "SQL_CONCAT" // fmt.Sprintf / + used to build SQL
	ruleSQLInterp = "SQL_INTERP" // user value interpolated into SQL text
)

type finding struct {
	rule string
	file string
	line int
	what string
}

func (f finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.file, f.line, f.rule, f.what)
}

func scanFile(path string) ([]finding, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil
	}
	var out []finding
	c := &checker{fset: fset}
	ast.Inspect(node, func(n ast.Node) bool {
		if f := c.check(n); f != nil {
			out = append(out, f...)
		}
		return true
	})
	return out, nil
}

type checker struct {
	fset *token.FileSet
}

func (c *checker) check(n ast.Node) []finding {
	switch x := n.(type) {
	case *ast.CallExpr:
		// R1/R2: fmt.Sprintf is the single function that can do both.
		if isFmtSprintf(x) {
			if len(x.Args) == 0 {
				return nil
			}
			formatLit, ok := x.Args[0].(*ast.BasicLit)
			if !ok || formatLit.Kind != token.STRING {
				return nil
			}
			upper := strings.ToUpper(unquote(formatLit.Value))
			if !isSQL(upper) {
				return nil
			}
			// R2: a placeholder verb means a user value is interpolated
			// into the SQL text — the precise mechanism by which an
			// identifier (table/column/ORDER BY) could leak in.
			// Verbs are compared against the upper-cased format string,
			// so a literal "%s" in source becomes "%S" here.
			if hasPlaceholder(upper) {
				return []finding{{
					rule: ruleSQLInterp,
					file: c.fset.Position(x.Pos()).Filename,
					line: c.fset.Position(x.Pos()).Line,
					what: "user value interpolated into SQL text via format verb; use parameter binding so identifiers cannot leak in",
				}}
			}
			// R1: even without a verb, building SQL with Sprintf is the
			// concatenation pattern the design forbids.
			return []finding{{
				rule: ruleSQLConcat,
				file: c.fset.Position(x.Pos()).Filename,
				line: c.fset.Position(x.Pos()).Line,
				what: "fmt.Sprintf used to build SQL; use parameter binding instead",
			}}
		}
	case *ast.BinaryExpr:
		// R1: "SELECT ..." + var + "..." — string concatenation of SQL.
		if x.Op == token.ADD && isSQLString(x.X) {
			return []finding{{
				rule: ruleSQLConcat,
				file: c.fset.Position(x.Pos()).Filename,
				line: c.fset.Position(x.Pos()).Line,
				what: "string concatenation used to build SQL; use parameter binding instead",
			}}
		}
	}
	return nil
}

func isFmtSprintf(x *ast.CallExpr) bool {
	fn, ok := x.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := fn.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "fmt" && fn.Sel.Name == "Sprintf"
}

// isSQLString reports whether the expression is a string literal that begins
// a SQL statement built by concatenation. Only the left operand of a "+" is
// considered, so a trailing literal is not a false positive.
func isSQLString(e ast.Expr) bool {
	s, ok := e.(*ast.BasicLit)
	if !ok {
		return false
	}
	if s.Kind != token.STRING {
		return false
	}
	return isSQL(strings.ToUpper(unquote(s.Value)))
}

func unquote(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func isSQL(upper string) bool {
	for _, kw := range []string{
		"SELECT ", "INSERT ", "UPDATE ", "DELETE ",
		"CREATE ", "DROP ", "ALTER ", "ORDER BY", "FROM ", "WHERE ",
	} {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}

// hasPlaceholder reports whether a format string contains a verb that
// interpolates an argument into the text — the mechanism by which a
// variable could end up as a SQL identifier. The input is already
// upper-cased, so the verbs are matched in upper case.
func hasPlaceholder(upper string) bool {
	for _, v := range []string{
		"%S", "%V", "%Q", "%D", "%X", "%T", "%P", "%G", "%F", "%C", "%B",
	} {
		if strings.Contains(upper, v) {
			return true
		}
	}
	return false
}

func scan(root string) ([]finding, error) {
	var out []finding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.Contains(path, "sqlscan") {
			return nil
		}
		f, err := scanFile(path)
		if err != nil {
			return err
		}
		out = append(out, f...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sqlscan scan <dir> [<dir> ...]")
		os.Exit(2)
	}
	if os.Args[1] != "scan" {
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
	var all []finding
	for _, root := range os.Args[2:] {
		f, err := scan(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %s: %v\n", root, err)
			os.Exit(1)
		}
		all = append(all, f...)
	}
	for _, f := range all {
		fmt.Println(f)
	}
	if len(all) > 0 {
		os.Exit(1)
	}
}
