//go:build vendored

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlayerAssetHandlersServeVendoredAssets(t *testing.T) {
	srv := &Server{}
	mux := srv.newMux()

	cssReq := httptest.NewRequest(http.MethodGet, playerCSSPath, nil)
	cssRec := httptest.NewRecorder()
	mux.ServeHTTP(cssRec, cssReq)

	if cssRec.Code != http.StatusOK {
		t.Fatalf("CSS status = %d, want %d", cssRec.Code, http.StatusOK)
	}
	if got := cssRec.Header().Get("Content-Type"); got != "text/css; charset=utf-8" {
		t.Fatalf("CSS content-type = %q", got)
	}
	if !strings.Contains(cssRec.Body.String(), ".asciinema-player") {
		t.Fatalf("expected CSS body to contain player styles")
	}

	jsReq := httptest.NewRequest(http.MethodGet, playerJSPath, nil)
	jsRec := httptest.NewRecorder()
	mux.ServeHTTP(jsRec, jsReq)

	if jsRec.Code != http.StatusOK {
		t.Fatalf("JS status = %d, want %d", jsRec.Code, http.StatusOK)
	}
	if got := jsRec.Header().Get("Content-Type"); got != "application/javascript; charset=utf-8" {
		t.Fatalf("JS content-type = %q", got)
	}
	if !strings.Contains(jsRec.Body.String(), "AsciinemaPlayer") {
		t.Fatalf("expected JS body to contain bundled player symbol")
	}
}

func TestRenderPlayerPageUsesVendoredAssets(t *testing.T) {
	srv := &Server{}

	page, err := srv.renderPlayerPage("host-a", "1234567890abcdef", "12 KB", 3, "Apr 12 12:00:00", "Apr 12 12:05:00", "host-a/1234567890abcdef")
	if err != nil {
		t.Fatalf("renderPlayerPage() error = %v", err)
	}

	if !strings.Contains(page, `href="`+playerCSSPath+`"`) {
		t.Fatalf("expected page to reference vendored CSS path")
	}
	if !strings.Contains(page, `src="`+playerJSPath+`"`) {
		t.Fatalf("expected page to reference vendored JS path")
	}
	if strings.Contains(page, "cdn.jsdelivr.net") {
		t.Fatalf("did not expect CDN URL in vendored build")
	}
}
