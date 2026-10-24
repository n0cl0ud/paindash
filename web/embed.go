// Package web embeds the built React UI (web/dist, produced by `make web`).
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
