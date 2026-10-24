// Package enrich fetches exploitability signals: the CISA Known Exploited
// Vulnerabilities catalog and FIRST EPSS scores.
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/store"
)

const (
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://api.first.org/data/v1/epss"
)

type Client struct {
	KEVURL  string
	EPSSURL string
	HTTP    *http.Client
}

// KEV returns the catalog as CVE ID -> date added.
func (c *Client) KEV(ctx context.Context) (map[string]time.Time, error) {
	var body struct {
		Vulnerabilities []struct {
			CVEID     string `json:"cveID"`
			DateAdded string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := c.get(ctx, or(c.KEVURL, DefaultKEVURL), &body); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	out := make(map[string]time.Time, len(body.Vulnerabilities))
	for _, v := range body.Vulnerabilities {
		t, _ := time.Parse(time.DateOnly, v.DateAdded)
		out[v.CVEID] = t
	}
	return out, nil
}

// EPSS returns the scores of the given CVEs, querying the API in batches.
func (c *Client) EPSS(ctx context.Context, cves []string) (map[string]store.EPSS, error) {
	out := map[string]store.EPSS{}
	const batch = 100
	for i := 0; i < len(cves); i += batch {
		chunk := cves[i:min(i+batch, len(cves))]
		var body struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		u := or(c.EPSSURL, DefaultEPSSURL) + "?" + url.Values{"cve": {strings.Join(chunk, ",")}, "limit": {strconv.Itoa(batch)}}.Encode()
		if err := c.get(ctx, u, &body); err != nil {
			return out, fmt.Errorf("epss: %w", err)
		}
		for _, d := range body.Data {
			score, err1 := strconv.ParseFloat(d.EPSS, 64)
			pct, err2 := strconv.ParseFloat(d.Percentile, 64)
			if err1 == nil && err2 == nil {
				out[d.CVE] = store.EPSS{Score: score, Percentile: pct}
			}
		}
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, u string, into any) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "paindash")
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
