//go:build vendored

package server

import (
	"embed"
	"net/http"
)

//go:embed assets/asciinema-player.css assets/asciinema-player.min.js
var playerAssetFS embed.FS

type playerAssetBundle struct {
	CSS []byte
	JS  []byte
}

var playerAssets = playerAssetBundle{
	CSS: mustReadPlayerAsset("assets/asciinema-player.css"),
	JS:  mustReadPlayerAsset("assets/asciinema-player.min.js"),
}

func mustReadPlayerAsset(path string) []byte {
	data, err := playerAssetFS.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}

func registerPlayerAssetHandlers(mux *http.ServeMux, s *Server) {
	mux.HandleFunc(playerCSSPath, s.handlePlayerCSS)
	mux.HandleFunc(playerJSPath, s.handlePlayerJS)
}

func (s *Server) playerAssetURLs() (string, string, error) {
	return playerCSSPath, playerJSPath, nil
}

func (s *Server) handlePlayerCSS(w http.ResponseWriter, _ *http.Request) {
	writePlayerAsset(w, "text/css; charset=utf-8", playerAssets.CSS)
}

func (s *Server) handlePlayerJS(w http.ResponseWriter, _ *http.Request) {
	writePlayerAsset(w, "application/javascript; charset=utf-8", playerAssets.JS)
}

func writePlayerAsset(w http.ResponseWriter, contentType string, data []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}
