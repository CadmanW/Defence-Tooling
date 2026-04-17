//go:build !vendored

package server

import (
	"strings"
	"testing"
)

func TestRenderPlayerPageUsesCDNAssets(t *testing.T) {
	srv := &Server{}

	page, err := srv.renderPlayerPage("host-a", "1234567890abcdef", "12 KB", 3, "Apr 12 12:00:00", "Apr 12 12:05:00", "host-a/1234567890abcdef")
	if err != nil {
		t.Fatalf("renderPlayerPage() error = %v", err)
	}

	version, err := loadPlayerVersion()
	if err != nil {
		t.Fatalf("loadPlayerVersion() error = %v", err)
	}

	expectedCSS := "https://cdn.jsdelivr.net/npm/asciinema-player@" + version + "/dist/bundle/asciinema-player.css"
	expectedJS := "https://cdn.jsdelivr.net/npm/asciinema-player@" + version + "/dist/bundle/asciinema-player.min.js"
	if !strings.Contains(page, `href="`+expectedCSS+`"`) {
		t.Fatalf("expected page to reference CDN CSS URL")
	}
	if !strings.Contains(page, `src="`+expectedJS+`"`) {
		t.Fatalf("expected page to reference CDN JS URL")
	}
	if strings.Contains(page, `href="`+playerCSSPath+`"`) {
		t.Fatalf("did not expect vendored CSS path in default build")
	}
	if strings.Contains(page, `src="`+playerJSPath+`"`) {
		t.Fatalf("did not expect vendored JS path in default build")
	}
}
