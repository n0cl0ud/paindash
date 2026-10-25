package auth

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed pages.html
var pagesHTML string

var pages = template.Must(template.New("page").Parse(pagesHTML))

// page is a sign-in, sign-out or error page, served without the UI (which
// needs a session) and without script.
type page struct {
	Title    string
	Message  string
	Error    string
	Form     bool   // the sign-in form of local accounts
	RD       string // where the form goes back after sign-in
	Email    string // kept in the form after a failed attempt
	Link     string
	LinkText string
}

func (a *Sessions) render(w http.ResponseWriter, status int, p page) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pages.Execute(w, p); err != nil {
		a.log.Error("auth page", "err", err)
	}
}
