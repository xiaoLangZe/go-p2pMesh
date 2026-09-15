package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSelfTest plants deliberately violating samples and asserts the
// scanner catches each one. This is the "the checker itself has a test"
// requirement from D10: if the checker cannot detect a planted violation,
// every "pass" it reports on real code is meaningless.
func TestSelfTest(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "fmt.Sprintf interpolating user value into SQL",
			src:  "package x\nimport \"fmt\"\nfunc f(u string) string { return fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", u) }",
			want: ruleSQLInterp,
		},
		{
			name: "string concat building SQL",
			src:  "package x\nfunc f(u string) string { return \"SELECT * FROM users WHERE id = \" + u }",
			want: ruleSQLConcat,
		},
		{
			name: "plain string literal is fine",
			src:  "package x\nfunc f() string { return \"hello world\" }",
			want: "",
		},
		{
			name: "parameter binding is fine",
			src:  "package x\nimport \"database/sql\"\nfunc f(db *sql.DB, id string) { db.Exec(\"SELECT * FROM users WHERE id = ?\", id) }",
			want: "",
		},
		{
			name: "fmt.Sprintf on non-SQL is fine",
			src:  "package x\nimport \"fmt\"\nfunc f(n int) string { return fmt.Sprintf(\"count=%d\", n) }",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "sample.go")
			if err := os.WriteFile(p, []byte(c.src), 0o644); err != nil {
				t.Fatal(err)
			}
			f, err := scanFile(p)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if c.want == "" {
				if len(f) != 0 {
					t.Errorf("expected no findings, got %v", f)
				}
				return
			}
			found := false
			for _, ff := range f {
				if ff.rule == c.want {
					found = true
				}
			}
			if !found {
				t.Errorf("expected a %s finding, got %v", c.want, f)
			}
		})
	}
}

// TestSelfTestCommentNotFlagged ensures a comment mentioning fmt.Sprintf
// is not reported — the AST-based approach must not grep comments. The
// real call on line 4 is flagged; the comment on line 2 is not.
func TestSelfTestCommentNotFlagged(t *testing.T) {
	src := "package x\n// Do not use fmt.Sprintf to build SQL here.\nimport \"fmt\"\nfunc f() string { return fmt.Sprintf(\"SELECT * FROM t\", 1) }"
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := scanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) == 0 {
		t.Fatal("expected the real fmt.Sprintf call to be flagged")
	}
	for _, ff := range f {
		if ff.line != 4 {
			t.Errorf("finding on line %d, want 4 (the call, not the comment)", ff.line)
		}
	}
}

func TestSelfTestSQLKeywordOnlyLeftOperand(t *testing.T) {
	src := "package x\nfunc f(u string) string { return \"SELECT * FROM users WHERE id = \" + u + \" AND active = 1\"}"
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := scanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) == 0 {
		t.Fatal("expected a concat finding for the SQL-bearing left operand")
	}
}

func TestSelfTestUnparseableDoesNotCrash(t *testing.T) {
	src := "package x\nfunc f( {"
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := scanFile(p)
	if err != nil {
		t.Fatalf("scan must not error on unparseable input: %v", err)
	}
	if len(f) != 0 {
		t.Errorf("expected no findings from broken source, got %v", f)
	}
}
