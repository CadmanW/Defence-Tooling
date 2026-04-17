package server

import (
	"embed"
	"fmt"
	"strings"
	"sync"
)

const (
	playerCSSPath = "/assets/asciinema-player.css"
	playerJSPath  = "/assets/asciinema-player.min.js"

	playerVersionFile = "assets/asciinema-player.version"
)

//go:embed assets/asciinema-player.version
var playerVersionFS embed.FS

var (
	playerVersionOnce sync.Once
	playerVersion     string
	playerVersionErr  error
)

func loadPlayerVersion() (string, error) {
	playerVersionOnce.Do(func() {
		data, err := playerVersionFS.ReadFile(playerVersionFile)
		if err != nil {
			playerVersionErr = fmt.Errorf("read player version: %w", err)
			return
		}

		playerVersion = strings.TrimSpace(string(data))
		if playerVersion == "" {
			playerVersionErr = fmt.Errorf("read player version: empty version")
		}
	})

	return playerVersion, playerVersionErr
}
