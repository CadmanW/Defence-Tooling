//go:build !vendored

package server

import (
	"fmt"
	"net/http"
)

func registerPlayerAssetHandlers(_ *http.ServeMux, _ *Server) {}

func (s *Server) playerAssetURLs() (string, string, error) {
	version, err := loadPlayerVersion()
	if err != nil {
		return "", "", err
	}

	base := fmt.Sprintf("https://cdn.jsdelivr.net/npm/asciinema-player@%s/dist/bundle/", version)
	return base + "asciinema-player.css", base + "asciinema-player.min.js", nil
}
