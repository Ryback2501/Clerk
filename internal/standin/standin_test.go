package standin

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The stand-in signs anyone in as an administrator, so it must never reach the
// binary: only test files may import this package.
func TestOnlyTestFilesImportTheStandIn(t *testing.T) {
	root := filepath.Join("..", "..")
	self := filepath.Join(root, "internal", "standin")
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			if path == self {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasSuffix(importPath, "/internal/standin") {
				t.Errorf("%s imports the test-only stand-in package", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
