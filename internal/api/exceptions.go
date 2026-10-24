package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/auth"
	"github.com/n0cl0ud/paindash/internal/model"
)

// MaxExceptionLifetime caps how long an exception can hide a finding.
const MaxExceptionLifetime = 180 * 24 * time.Hour

func (s *Server) exceptions(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.Exceptions(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []model.Exception{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type exceptionInput struct {
	VulnID        string    `json:"vulnId"`
	Package       string    `json:"package"`
	Namespace     string    `json:"namespace"`
	Workload      string    `json:"workload"`
	Justification string    `json:"justification"`
	Statement     string    `json:"statement"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

func (in exceptionInput) validate(now time.Time) error {
	switch {
	case strings.TrimSpace(in.VulnID) == "" || strings.TrimSpace(in.Package) == "":
		return fmt.Errorf("vulnId and package are required")
	case in.Workload != "" && in.Namespace == "":
		return fmt.Errorf("a workload exception needs its namespace")
	case !slices.Contains(model.VexJustifications, in.Justification):
		return fmt.Errorf("unknown justification %q", in.Justification)
	case len(strings.TrimSpace(in.Statement)) < 10:
		return fmt.Errorf("the statement must explain why, in at least 10 characters")
	case !in.ExpiresAt.After(now):
		return fmt.Errorf("expiresAt must be in the future")
	case in.ExpiresAt.Sub(now) > MaxExceptionLifetime:
		return fmt.Errorf("an exception expires within 180 days at most")
	}
	return nil
}

func (s *Server) addException(w http.ResponseWriter, r *http.Request) {
	if !s.writeAllowed(w, r) {
		return
	}
	var in exceptionInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if err := in.validate(time.Now()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	e, err := s.Store.AddException(r.Context(), model.Exception{
		VulnID: strings.TrimSpace(in.VulnID), Package: strings.TrimSpace(in.Package),
		Namespace: in.Namespace, Workload: in.Workload, Justification: in.Justification,
		Statement: strings.TrimSpace(in.Statement), Author: s.author(r), ExpiresAt: in.ExpiresAt,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.announce(r, e, model.EventExceptionAdd, fmt.Sprintf("Exception added: %s in %s%s, until %s (%s)",
		e.VulnID, e.Package, scopeLabel(e), e.ExpiresAt.UTC().Format("Jan 2, 2006"), e.Author))
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) revokeException(w http.ResponseWriter, r *http.Request) {
	if !s.writeAllowed(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	e, ok, err := s.Store.RevokeException(r.Context(), id, s.author(r))
	switch {
	case err != nil:
		s.fail(w, err)
		return
	case !ok:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no active exception with this id"})
		return
	}
	s.announce(r, e, model.EventExceptionRev, fmt.Sprintf("Exception revoked: %s in %s%s (%s)", e.VulnID, e.Package, scopeLabel(e), s.author(r)))
	writeJSON(w, http.StatusOK, e)
}

// openVEX exports the active exceptions as an OpenVEX document, for auditors.
func (s *Server) openVEX(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.Exceptions(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	type product struct {
		ID string `json:"@id"`
	}
	type statement struct {
		Vulnerability   map[string]string `json:"vulnerability"`
		Products        []product         `json:"products"`
		Status          string            `json:"status"`
		Justification   string            `json:"justification"`
		ImpactStatement string            `json:"impact_statement"`
		Timestamp       time.Time         `json:"timestamp"`
	}
	now := time.Now().UTC()
	doc := map[string]any{
		"@context":  "https://openvex.dev/ns/v0.2.0",
		"@id":       "urn:paindash:vex:" + strconv.FormatInt(now.Unix(), 10),
		"author":    "paindash",
		"timestamp": now,
		"version":   1,
	}
	stmts := []statement{}
	for _, e := range items {
		if st := e.StateAt(now); st != "active" && st != "expiring" {
			continue
		}
		// Products are named by package (a generic purl: exceptions match the
		// package name whatever its ecosystem) and, when narrowed, k8s scope.
		id := "pkg:generic/" + url.PathEscape(e.Package)
		if e.Namespace != "" {
			id += "?k8s-namespace=" + url.QueryEscape(e.Namespace)
			if e.Workload != "" {
				id += "&k8s-workload=" + url.QueryEscape(e.Workload)
			}
		}
		stmts = append(stmts, statement{
			Vulnerability: map[string]string{"name": e.VulnID}, Products: []product{{ID: id}},
			Status: "not_affected", Justification: e.Justification,
			ImpactStatement: fmt.Sprintf("%s (by %s, expires %s)", e.Statement, e.Author, e.ExpiresAt.UTC().Format(time.RFC3339)),
			Timestamp:       e.CreatedAt.UTC(),
		})
	}
	doc["statements"] = stmts
	w.Header().Set("Content-Disposition", `attachment; filename="paindash.openvex.json"`)
	writeJSON(w, http.StatusOK, doc)
}

// writeAllowed guards state-changing requests against cross-site requests:
// a browser cannot send a JSON body to another origin without a CORS
// preflight, which this server never grants.
func (s *Server) writeAllowed(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	site := r.Header.Get("Sec-Fetch-Site")
	if !strings.HasPrefix(ct, "application/json") || (site != "" && site != "same-origin") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site or non-JSON write refused"})
		return false
	}
	if s.Auth != nil && auth.UserFrom(r.Context()) == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no identity"})
		return false
	}
	return true
}

// author is who did it, from the Pomerium identity.
func (s *Server) author(r *http.Request) string {
	if u := auth.UserFrom(r.Context()); u != nil && u.Email != "" {
		return u.Email
	}
	return "anonymous" // authentication disabled
}

// announce records an exception change in the feed of each env where it
// covers something (and so in their history), or of every env if none.
func (s *Server) announce(r *http.Request, e model.Exception, typ model.EventType, title string) {
	envs, err := s.Store.ExceptionEnvs(r.Context(), e)
	if err != nil {
		s.Log.Warn("exception envs", "err", err)
	}
	if len(envs) == 0 {
		envs = []string{model.AllEnvs}
	}
	for _, env := range envs {
		ev := model.LiveEvent{Env: env, Type: typ, Title: title}
		if err := s.Store.AddEvent(r.Context(), &ev); err != nil {
			s.Log.Error("store event", "err", err)
			return
		}
		s.Hub.Publish(&ev)
	}
	s.Hub.Invalidate(model.AllEnvs)
}

func scopeLabel(e model.Exception) string {
	switch {
	case e.Workload != "":
		return " (" + e.Namespace + "/" + e.Workload + ")"
	case e.Namespace != "":
		return " (namespace " + e.Namespace + ")"
	}
	return ""
}
