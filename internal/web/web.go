// Package web holds the static assets shared by the two interfaces Clerk
// serves: the administration UI and the end-user login page.
//
// They live here rather than in either package so the assets are embedded
// once, and so the login page does not have to reach into the admin package
// for it — internal/oidc must not depend on internal/admin.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:static
var staticFS embed.FS

// StaticPath is the default URL prefix the assets are served under.
const StaticPath = "/static/"

// StylesheetFile is the stylesheet's name within the asset tree.
const StylesheetFile = "pico.min.css"

// Stylesheet is the stylesheet's URL under the default prefix.
const Stylesheet = StaticPath + StylesheetFile

// Mux is the part of *http.ServeMux that registers routes. Taking it rather
// than the concrete router lets a test record exactly which routes the code
// registers.
type Mux interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// Register mounts the static assets at the default prefix.
func Register(mux Mux) { RegisterAt(mux, StaticPath) }

// RegisterAt mounts the static assets at prefix, which must begin and end with
// a slash. The OIDC endpoints serve them under the issuer's path as well, so a
// proxy forwarding only that prefix still reaches them.
func RegisterAt(mux Mux, prefix string) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// The tree is embedded at build time, so this cannot fail in a built
		// binary.
		panic("web: embedded static assets unavailable: " + err.Error())
	}
	mux.Handle("GET "+prefix, http.StripPrefix(prefix, http.FileServer(http.FS(noDirFS{sub}))))
}

// noDirFS refuses to open directories, so the file server cannot serve a
// browsable index of whatever ends up in the asset tree.
type noDirFS struct{ fs.FS }

func (f noDirFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, fs.ErrNotExist
	}
	return file, nil
}
