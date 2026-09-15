package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestStylesheetIsServed(t *testing.T) {
	rec := serve(t, Stylesheet)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", Stylesheet, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Errorf("Content-Type = %q, want a CSS type", ct)
	}
	if rec.Body.Len() < 1000 {
		t.Errorf("stylesheet is only %d bytes; the asset is probably missing", rec.Body.Len())
	}
}

func TestAdminAssetsAreServed(t *testing.T) {
	for _, tc := range []struct{ file, contentType string }{
		{"admin.css", "css"},
		{"admin.js", "javascript"},
		{"nunito.woff2", ""},
	} {
		rec := serve(t, StaticPath+tc.file)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.file, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.contentType) {
			t.Errorf("%s Content-Type = %q, want %s", tc.file, ct, tc.contentType)
		}
		if rec.Body.Len() < 1000 {
			t.Errorf("%s is only %d bytes; the asset is probably missing", tc.file, rec.Body.Len())
		}
	}
}

func TestAssetDirectoryIsNotBrowsable(t *testing.T) {
	rec := serve(t, StaticPath)
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "pico.min.css") {
		t.Error("the asset directory returns a browsable index")
	}
}
