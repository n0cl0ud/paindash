// Package store persists the inventory, SBOMs, findings and live events in
// Postgres. paindash runs as a single replica and is the only writer, so a
// version counter bumped on every write lets readers cache derived views.
package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/n0cl0ud/paindash/internal/model"
)

//go:embed migrations/*.sql
var migrations embed.FS

// State keys.
const (
	StateInventorySync = "inventory_last_sync"
	StateVulnDBBuilt   = "vulndb_built_at"
	StateVulnDBChecked = "vulndb_checked_at"
	StateKEVLoaded     = "kev_loaded"
	StateInitialScan   = "initial_scan_done"
	StateMatchRules    = "match_rules_version"
	StateExposure      = "exposure_available"
	// Exception markers recorded on every env's history were pruned.
	StateExceptionMarkers = "history_exception_markers_pruned"
)

type Store struct {
	pool    *pgxpool.Pool
	version atomic.Int64
}

// Open connects to Postgres. An empty url falls back to the standard libpq
// variables (PGHOST, PGUSER, PGPASSWORD, PGDATABASE, PGSSLMODE...), which
// keeps the password out of a URL where special characters would need
// escaping. maxConns caps the pool: the database server may be shared.
func Open(ctx context.Context, url string, maxConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Version changes after every committed write.
func (s *Store) Version() int64 { return s.version.Load() }

func (s *Store) changed() { s.version.Add(1) }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		sql, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7151)`); err != nil {
				return err
			}
			var done bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, e.Name()).Scan(&done); err != nil || done {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, e.Name())
			return err
		})
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	return nil
}

// ---- inventory --------------------------------------------------------------

const containerCols = `c.env, c.cluster, c.namespace, c.kind, c.name, c.container, c.image, i.ref, c.digest, c.exposure, c.first_seen, c.last_seen,
	COALESCE(i.source, ''), COALESCE(i.revision, '')`

func scanContainers(rows pgx.Rows) ([]model.Container, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.Container, error) {
		var c model.Container
		err := row.Scan(&c.Env, &c.Cluster, &c.Namespace, &c.Kind, &c.Name, &c.Container, &c.Image, &c.Ref, &c.Digest, &c.Exposure, &c.FirstSeen, &c.LastSeen,
			&c.Source, &c.Revision)
		return c, err
	})
}

func (s *Store) Containers(ctx context.Context) ([]model.Container, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+containerCols+` FROM containers c JOIN images i USING (digest)`)
	if err != nil {
		return nil, err
	}
	return scanContainers(rows)
}

func (s *Store) ContainersForDigest(ctx context.Context, digest string) ([]model.Container, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+containerCols+` FROM containers c JOIN images i USING (digest) WHERE c.digest = $1`, digest)
	if err != nil {
		return nil, err
	}
	return scanContainers(rows)
}

func (s *Store) ContainersForVuln(ctx context.Context, vulnID string) ([]model.Container, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+containerCols+` FROM containers c JOIN images i USING (digest)
		WHERE c.digest IN (SELECT digest FROM findings WHERE vuln_id = $1)`, vulnID)
	if err != nil {
		return nil, err
	}
	return scanContainers(rows)
}

// HasHistory reports whether paindash ever recorded an inventory, so the very
// first sync can stay quiet instead of announcing hundreds of "deployments".
func (s *Store) HasHistory(ctx context.Context) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM containers) OR EXISTS (SELECT 1 FROM deployments)`).Scan(&ok)
	return ok, err
}

type InventoryChange struct {
	Added    []model.Container
	Removed  []model.Container
	Exposed  []model.Container // still running, exposure changed
	Clusters []string          // clusters present in the snapshot: their rows get last_seen = now()
	Quiet    bool              // initial sync
}

func (s *Store) ApplyInventory(ctx context.Context, ch InventoryChange) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, c := range ch.Added {
			b.Queue(`INSERT INTO images (digest, ref, quiet) VALUES ($1, $2, $3) ON CONFLICT (digest) DO NOTHING`, c.Digest, c.Ref, ch.Quiet)
			b.Queue(`INSERT INTO containers (env, cluster, namespace, kind, name, container, digest, image, exposure)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING`,
				c.Env, c.Cluster, c.Namespace, c.Kind, c.Name, c.Container, c.Digest, c.Image, cmpOr(c.Exposure, model.ExposureNone))
			b.Queue(`INSERT INTO deployments (env, cluster, namespace, kind, name, container, digest, image)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				c.Env, c.Cluster, c.Namespace, c.Kind, c.Name, c.Container, c.Digest, c.Image)
		}
		for _, c := range ch.Exposed {
			b.Queue(`UPDATE containers SET exposure = $7
				WHERE cluster = $1 AND namespace = $2 AND kind = $3 AND name = $4 AND container = $5 AND digest = $6`,
				c.Cluster, c.Namespace, c.Kind, c.Name, c.Container, c.Digest, cmpOr(c.Exposure, model.ExposureNone))
		}
		for _, c := range ch.Removed {
			b.Queue(`DELETE FROM containers WHERE cluster = $1 AND namespace = $2 AND kind = $3 AND name = $4 AND container = $5 AND digest = $6`,
				c.Cluster, c.Namespace, c.Kind, c.Name, c.Container, c.Digest)
		}
		if len(ch.Added) > 0 || len(ch.Removed) > 0 {
			b.Queue(`UPDATE images i SET retired_at = NULL WHERE retired_at IS NOT NULL
				AND EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest)`)
			b.Queue(`UPDATE images i SET retired_at = now() WHERE retired_at IS NULL
				AND NOT EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest)`)
		}
		b.Queue(`UPDATE containers SET last_seen = now() WHERE cluster = ANY($1)`, ch.Clusters)
		b.Queue(`INSERT INTO state (key, value, updated_at) VALUES ($1, $2, now())
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()`,
			StateInventorySync, time.Now().UTC().Format(time.RFC3339))
		return tx.SendBatch(ctx, b).Close()
	})
	// last_seen and the sync time are not part of the read model: only a real
	// change of the inventory makes readers reload.
	if err == nil && len(ch.Added)+len(ch.Removed)+len(ch.Exposed) > 0 {
		s.changed()
	}
	return err
}

// Prune bounds the database size: images (with their SBOM and findings) that
// stopped running more than retention ago, older events, and repeated
// deployment rows (a CronJob run redeploys the same digest every time).
func (s *Store) Prune(ctx context.Context, retention time.Duration) (images int64, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		cutoff := time.Now().Add(-retention)
		tag, err := tx.Exec(ctx, `DELETE FROM images i WHERE retired_at < $1
			AND NOT EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest)`, cutoff)
		if err != nil {
			return err
		}
		images = tag.RowsAffected()
		if _, err := tx.Exec(ctx, `DELETE FROM events WHERE ts < $1`, cutoff); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM deployments d USING deployments n
			WHERE n.cluster = d.cluster AND n.namespace = d.namespace AND n.kind = d.kind
			  AND n.name = d.name AND n.container = d.container AND n.digest = d.digest AND n.id > d.id`)
		return err
	})
	if err == nil {
		s.changed()
	}
	return images, err
}

// PreviousImage returns the image the workload container ran before digest.
func (s *Store) PreviousImage(ctx context.Context, c model.Container) (digest, image string, ok bool, err error) {
	err = s.pool.QueryRow(ctx, `SELECT digest, image FROM deployments
		WHERE cluster = $1 AND namespace = $2 AND kind = $3 AND name = $4 AND container = $5 AND digest <> $6
		ORDER BY deployed_at DESC LIMIT 1`,
		c.Cluster, c.Namespace, c.Kind, c.Name, c.Container, c.Digest).Scan(&digest, &image)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	return digest, image, err == nil, err
}

// ---- scanning ---------------------------------------------------------------

func (s *Store) ResetScanning(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE images SET status = 'pending' WHERE status = 'scanning'`)
	return err
}

// ClaimImage picks the next running image to scan, images running in
// priorityEnv first.
func (s *Store) ClaimImage(ctx context.Context, priorityEnv string) (digest, ref string, quiet, ok bool, err error) {
	err = s.pool.QueryRow(ctx, `UPDATE images SET status = 'scanning', attempts = attempts + 1
		WHERE digest = (
			SELECT i.digest FROM images i
			WHERE i.status = 'pending' AND (i.retry_at IS NULL OR i.retry_at <= now())
			  AND EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest)
			ORDER BY EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest AND c.env = $1) DESC, i.first_seen
			LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING digest, ref, quiet`, priorityEnv).Scan(&digest, &ref, &quiet)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, false, nil
	}
	if err == nil {
		s.changed()
	}
	return digest, ref, quiet, err == nil, err
}

// FailScan records a failed attempt. It returns true when the image is given
// up on (status failed) rather than scheduled for a retry.
func (s *Store) FailScan(ctx context.Context, digest, msg string, maxAttempts int) (final bool, err error) {
	var status string
	err = s.pool.QueryRow(ctx, `UPDATE images SET
			status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'pending' END,
			retry_at = now() + attempts * interval '2 minutes',
			error = $2
		WHERE digest = $1 RETURNING status`, digest, msg, maxAttempts).Scan(&status)
	if err == nil {
		s.changed()
	}
	return status == "failed", err
}

// RetryFailed puts the images given up on back in the queue, with a fresh
// attempts budget: the cause may be gone (registry access, network policy).
func (s *Store) RetryFailed(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE images i SET status = 'pending', attempts = 0, retry_at = NULL
		WHERE status = 'failed' AND EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest)`)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() > 0 {
		s.changed()
	}
	return tag.RowsAffected(), nil
}

// PendingQuiet counts images of the initial inventory not scanned yet.
func (s *Store) PendingQuiet(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM images i WHERE quiet AND status IN ('pending', 'scanning')
		AND EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest)`).Scan(&n)
	return n, err
}

// RematchCandidates lists running images that have an SBOM.
func (s *Store) RematchCandidates(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT digest FROM images i WHERE status = 'scanned' AND sbom IS NOT NULL
		AND EXISTS (SELECT 1 FROM containers c WHERE c.digest = i.digest)`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (s *Store) SBOM(ctx context.Context, digest string) ([]byte, error) {
	var gz []byte
	if err := s.pool.QueryRow(ctx, `SELECT sbom FROM images WHERE digest = $1`, digest).Scan(&gz); err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// ProvenanceMissing lists the images with an SBOM whose labels were never read.
func (s *Store) ProvenanceMissing(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT digest FROM images WHERE sbom IS NOT NULL AND source IS NULL`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Provenance is where an image was built from, from its OCI labels.
type Provenance struct{ Source, Revision string }

// SetProvenance records where images were built from ("" when unlabeled).
func (s *Store) SetProvenance(ctx context.Context, provs map[string]Provenance) error {
	b := &pgx.Batch{}
	for digest, p := range provs {
		b.Queue(`UPDATE images SET source = $2, revision = $3 WHERE digest = $1`, digest, p.Source, p.Revision)
	}
	if err := s.pool.SendBatch(ctx, b).Close(); err != nil {
		return err
	}
	s.changed()
	return nil
}

type ScanChange struct {
	Added   []model.VulnRef // vulns that were not on this image before
	Removed []model.VulnRef
	NewKEV  []string // known vulns that just became KEV
}

// SaveMatches replaces the findings of an image and marks it scanned. sbom is
// nil on a rematch (the stored SBOM is kept).
func (s *Store) SaveMatches(ctx context.Context, digest string, sbom []byte, matches []model.Match, dbBuilt time.Time) (ScanChange, error) {
	var ch ScanChange
	var gz []byte
	if sbom != nil {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(sbom); err != nil {
			return ch, err
		}
		if err := w.Close(); err != nil {
			return ch, err
		}
		gz = buf.Bytes()
	}

	vulns := map[string]model.Vuln{}
	type fkey struct{ vuln, purl string }
	news := map[fkey]model.Match{}
	for _, m := range matches {
		vulns[m.Vuln.ID] = m.Vuln
		news[fkey{m.Vuln.ID, m.Pkg.PURL}] = m
	}
	ids := make([]string, 0, len(vulns))
	for id := range vulns {
		ids = append(ids, id)
	}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM images WHERE digest = $1 FOR UPDATE`, digest); err != nil {
			return err
		}
		// Previous state of the vulns, to detect KEV transitions.
		wasKEV := map[string]bool{}
		rows, err := tx.Query(ctx, `SELECT id, kev FROM vulns WHERE id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			var kev bool
			if err := rows.Scan(&id, &kev); err != nil {
				return err
			}
			wasKEV[id] = kev
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// Previous findings of the image.
		old := map[fkey]bool{}
		oldVulns := map[string]bool{}
		rows, err = tx.Query(ctx, `SELECT vuln_id, purl FROM findings WHERE digest = $1`, digest)
		if err != nil {
			return err
		}
		for rows.Next() {
			var k fkey
			if err := rows.Scan(&k.vuln, &k.purl); err != nil {
				return err
			}
			old[k] = true
			oldVulns[k.vuln] = true
		}
		if err := rows.Err(); err != nil {
			return err
		}

		b := &pgx.Batch{}
		for _, v := range vulns {
			b.Queue(`INSERT INTO vulns (id, aliases, severity, cvss, epss, epss_percentile, kev, kev_added, description, url)
				VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, false), $8, $9, $10)
				ON CONFLICT (id) DO UPDATE SET
					aliases = excluded.aliases, severity = excluded.severity, cvss = excluded.cvss,
					description = excluded.description, url = excluded.url,
					epss = COALESCE($5, vulns.epss), epss_percentile = COALESCE($6, vulns.epss_percentile),
					kev = vulns.kev OR COALESCE($7, false), kev_added = COALESCE(vulns.kev_added, $8),
					updated_at = now()`,
				v.ID, nonNil(v.Aliases), string(v.Severity), v.CVSS, v.EPSS, v.EPSSPercentile, v.KEV, v.KEVAddedAt, v.Description, v.URL)
			if v.KEV != nil && *v.KEV {
				if was, known := wasKEV[v.ID]; known && !was {
					ch.NewKEV = append(ch.NewKEV, v.ID)
				}
			}
		}
		for k := range old {
			if _, ok := news[k]; !ok {
				b.Queue(`DELETE FROM findings WHERE digest = $1 AND vuln_id = $2 AND purl = $3`, digest, k.vuln, k.purl)
			}
		}
		for k, m := range news {
			b.Queue(`INSERT INTO findings (digest, vuln_id, pkg_name, pkg_version, pkg_type, purl, fixed_in, source, location)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				ON CONFLICT (digest, vuln_id, purl) DO UPDATE SET
					pkg_name = excluded.pkg_name, pkg_version = excluded.pkg_version,
					pkg_type = excluded.pkg_type, fixed_in = excluded.fixed_in,
					source = excluded.source, location = excluded.location`,
				digest, k.vuln, m.Pkg.Name, m.Pkg.Version, m.Pkg.Type, k.purl, nonNil(m.FixedIn), m.Source, m.Location)
		}
		b.Queue(`UPDATE images SET status = 'scanned', error = NULL, retry_at = NULL,
				sbom = COALESCE($2, sbom), sbom_at = CASE WHEN $2::bytea IS NULL THEN sbom_at ELSE now() END,
				matched_at = now(), db_built_at = $3
			WHERE digest = $1`, digest, gz, nullTime(dbBuilt))
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}

		for id, v := range vulns {
			if !oldVulns[id] {
				ch.Added = append(ch.Added, model.VulnRef{ID: id, Severity: v.Severity, KEV: (v.KEV != nil && *v.KEV) || wasKEV[id]})
			}
		}
		var gone []string
		for id := range oldVulns {
			if _, ok := vulns[id]; !ok {
				gone = append(gone, id)
			}
		}
		if len(gone) > 0 {
			rows, err := tx.Query(ctx, `SELECT id, severity, kev FROM vulns WHERE id = ANY($1)`, gone)
			if err != nil {
				return err
			}
			ch.Removed, err = pgx.CollectRows(rows, scanVulnRef)
			return err
		}
		return nil
	})
	if err == nil {
		s.changed()
	}
	return ch, err
}

func scanVulnRef(row pgx.CollectableRow) (model.VulnRef, error) {
	var v model.VulnRef
	var sev string
	err := row.Scan(&v.ID, &sev, &v.KEV)
	v.Severity = model.Severity(sev)
	return v, err
}

func (s *Store) VulnRefs(ctx context.Context, ids []string) (map[string]model.VulnRef, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, severity, kev FROM vulns WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	refs, err := pgx.CollectRows(rows, scanVulnRef)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.VulnRef, len(refs))
	for _, r := range refs {
		out[r.ID] = r
	}
	return out, nil
}

// DeployedBefore reports whether this workload container already ran this
// digest before the deployment just recorded (e.g. a CronJob run).
func (s *Store) DeployedBefore(ctx context.Context, c model.Container) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM deployments
		WHERE cluster = $1 AND namespace = $2 AND kind = $3 AND name = $4 AND container = $5 AND digest = $6`,
		c.Cluster, c.Namespace, c.Kind, c.Name, c.Container, c.Digest).Scan(&n)
	return n > 1, err
}

// ImageVulns lists the distinct vulns of a scanned image.
func (s *Store) ImageVulns(ctx context.Context, digest string) ([]model.VulnRef, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT v.id, v.severity, v.kev FROM findings f JOIN vulns v ON v.id = f.vuln_id WHERE f.digest = $1`, digest)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanVulnRef)
}

// CompareImages diffs the vulns of two images. ok is false unless both are scanned.
func (s *Store) CompareImages(ctx context.Context, oldDigest, newDigest string) (added, removed []model.VulnRef, ok bool, err error) {
	var scanned int
	if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM images WHERE digest IN ($1, $2) AND status = 'scanned'`, oldDigest, newDigest).Scan(&scanned); err != nil || scanned != 2 {
		return nil, nil, false, err
	}
	const q = `SELECT DISTINCT v.id, v.severity, v.kev FROM findings f JOIN vulns v ON v.id = f.vuln_id
		WHERE f.digest = $1 AND f.vuln_id NOT IN (SELECT vuln_id FROM findings WHERE digest = $2)`
	rows, err := s.pool.Query(ctx, q, newDigest, oldDigest)
	if err != nil {
		return nil, nil, false, err
	}
	if added, err = pgx.CollectRows(rows, scanVulnRef); err != nil {
		return nil, nil, false, err
	}
	rows, err = s.pool.Query(ctx, q, oldDigest, newDigest)
	if err != nil {
		return nil, nil, false, err
	}
	removed, err = pgx.CollectRows(rows, scanVulnRef)
	return added, removed, err == nil, err
}

func (s *Store) ImageScanned(ctx context.Context, digest string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM images WHERE digest = $1 AND status = 'scanned')`, digest).Scan(&ok)
	return ok, err
}

// ---- enrichment -------------------------------------------------------------

func (s *Store) CVEIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM vulns WHERE id LIKE 'CVE-%'`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

type EPSS struct{ Score, Percentile float64 }

func (s *Store) SetEPSS(ctx context.Context, scores map[string]EPSS) error {
	if len(scores) == 0 {
		return nil
	}
	ids := make([]string, 0, len(scores))
	sc := make([]float64, 0, len(scores))
	pc := make([]float64, 0, len(scores))
	for id, e := range scores {
		ids, sc, pc = append(ids, id), append(sc, e.Score), append(pc, e.Percentile)
	}
	_, err := s.pool.Exec(ctx, `UPDATE vulns v SET epss = e.score, epss_percentile = e.pct
		FROM unnest($1::text[], $2::double precision[], $3::double precision[]) AS e(id, score, pct)
		WHERE v.id = e.id`, ids, sc, pc)
	if err == nil {
		s.changed()
	}
	return err
}

// MarkKEV flags vulns listed in the CISA KEV catalog and returns the ones that
// were not flagged yet.
func (s *Store) MarkKEV(ctx context.Context, catalog map[string]time.Time) ([]string, error) {
	if len(catalog) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(catalog))
	added := make([]time.Time, 0, len(catalog))
	for id, t := range catalog {
		ids, added = append(ids, id), append(added, t)
	}
	rows, err := s.pool.Query(ctx, `UPDATE vulns v SET kev = true, kev_added = k.added
		FROM unnest($1::text[], $2::timestamptz[]) AS k(id, added)
		WHERE v.id = k.id AND NOT v.kev RETURNING v.id`, ids, added)
	if err != nil {
		return nil, err
	}
	newly, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err == nil && len(newly) > 0 {
		s.changed()
	}
	return newly, err
}

// ---- events & state ---------------------------------------------------------

func (s *Store) AddEvent(ctx context.Context, ev *model.LiveEvent) error {
	var workload, delta []byte
	var sev *string
	var err error
	if ev.Severity != nil {
		s := string(*ev.Severity)
		sev = &s
	}
	if ev.Workload != nil {
		if workload, err = json.Marshal(ev.Workload); err != nil {
			return err
		}
	}
	if ev.Delta != nil {
		if delta, err = json.Marshal(ev.Delta); err != nil {
			return err
		}
	}
	return s.pool.QueryRow(ctx, `INSERT INTO events (env, cluster, type, title, severity, workload, image, delta)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, ts`,
		ev.Env, ev.Cluster, string(ev.Type), ev.Title, sev, workload, ev.Image, delta).Scan(&ev.ID, &ev.TS)
}

func (s *Store) Events(ctx context.Context, env string, limit int) ([]model.LiveEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, ts, env, cluster, type, title, severity, workload, image, delta
		FROM events WHERE env = $1 OR env = '*' ORDER BY id DESC LIMIT $2`, env, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanEvent)
}

func scanEvent(row pgx.CollectableRow) (model.LiveEvent, error) {
	var ev model.LiveEvent
	var typ string
	var sev *string
	var workload, delta []byte
	if err := row.Scan(&ev.ID, &ev.TS, &ev.Env, &ev.Cluster, &typ, &ev.Title, &sev, &workload, &ev.Image, &delta); err != nil {
		return ev, err
	}
	ev.Type = model.EventType(typ)
	if sev != nil {
		severity := model.Severity(*sev)
		ev.Severity = &severity
	}
	if workload != nil {
		ev.Workload = &model.WorkloadRef{}
		if err := json.Unmarshal(workload, ev.Workload); err != nil {
			return ev, err
		}
	}
	if delta != nil {
		ev.Delta = &model.Delta{}
		if err := json.Unmarshal(delta, ev.Delta); err != nil {
			return ev, err
		}
	}
	return ev, nil
}

// EventsSince lists the events of env (and of all envs) after since, oldest
// first.
func (s *Store) EventsSince(ctx context.Context, env string, since time.Time, limit int) ([]model.LiveEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, ts, env, cluster, type, title, severity, workload, image, delta
		FROM events WHERE (env = $1 OR env = '*') AND ts > $2 ORDER BY id LIMIT $3`, env, since, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanEvent)
}

// ExceptionEnvs lists the envs where an exception covers a running container
// (whatever its state): where adding, revoking or expiring it moves the numbers.
func (s *Store) ExceptionEnvs(ctx context.Context, e model.Exception) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+containerCols+` FROM containers c JOIN images i USING (digest)
		WHERE c.digest IN (SELECT digest FROM findings WHERE vuln_id = $1 AND pkg_name = $2)`, e.VulnID, e.Package)
	if err != nil {
		return nil, err
	}
	cs, err := scanContainers(rows)
	if err != nil {
		return nil, err
	}
	var envs []string
	for _, c := range cs {
		if e.Covers(e.VulnID, e.Package, model.AffectedContainer{WorkloadRef: c.WorkloadRef}) && !slices.Contains(envs, c.Env) {
			envs = append(envs, c.Env)
		}
	}
	sort.Strings(envs)
	return envs, nil
}

// ---- history ----------------------------------------------------------------

func (s *Store) AddHistory(ctx context.Context, env string, p model.HistoryPoint) error {
	changes, err := json.Marshal(nonNil(p.Changes))
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO history (env, taken_at, kev, critical_fixable, high_fixable_internet, excepted, changes)
		VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`,
		env, p.At, p.KEV, p.CriticalFixable, p.HighFixableInternet, p.Excepted, changes)
	return err
}

// History returns the points of every env taken since since, preceded by the
// last one before it (the value at the start of the window), oldest first.
func (s *Store) History(ctx context.Context, since time.Time) (map[string][]model.HistoryPoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT env, taken_at, kev, critical_fixable, high_fixable_internet, excepted, changes FROM history WHERE taken_at >= $1
		UNION ALL
		SELECT DISTINCT ON (env) env, taken_at, kev, critical_fixable, high_fixable_internet, excepted, '[]'::jsonb
			FROM history WHERE taken_at < $1 ORDER BY env, taken_at DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]model.HistoryPoint{}
	for rows.Next() {
		var env string
		var p model.HistoryPoint
		var changes []byte
		if err := rows.Scan(&env, &p.At, &p.KEV, &p.CriticalFixable, &p.HighFixableInternet, &p.Excepted, &changes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(changes, &p.Changes); err != nil {
			return nil, err
		}
		out[env] = append(out[env], p)
	}
	for _, ps := range out {
		sort.Slice(ps, func(i, j int) bool { return ps[i].At.Before(ps[j].At) })
	}
	return out, rows.Err()
}

// LastHistory returns the latest point of each env.
func (s *Store) LastHistory(ctx context.Context) (map[string]model.HistoryPoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (env) env, taken_at, kev, critical_fixable, high_fixable_internet, excepted
		FROM history ORDER BY env, taken_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]model.HistoryPoint{}
	for rows.Next() {
		var env string
		var p model.HistoryPoint
		if err := rows.Scan(&env, &p.At, &p.KEV, &p.CriticalFixable, &p.HighFixableInternet, &p.Excepted); err != nil {
			return nil, err
		}
		out[env] = p
	}
	return out, rows.Err()
}

// PruneExceptionMarkers drops the exception changes of the history points
// whose excepted count did not move: exception events used to be recorded for
// every env, whether or not the exception covered anything there.
func (s *Store) PruneExceptionMarkers(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT env, taken_at, excepted, changes FROM history ORDER BY env, taken_at`)
	if err != nil {
		return 0, err
	}
	b := &pgx.Batch{}
	prevEnv, prevExcepted := "", -1
	for rows.Next() {
		var env string
		var at time.Time
		var excepted int
		var raw []byte
		if err := rows.Scan(&env, &at, &excepted, &raw); err != nil {
			return 0, err
		}
		if env != prevEnv {
			prevEnv, prevExcepted = env, -1
		}
		var changes []model.HistoryChange
		if err := json.Unmarshal(raw, &changes); err == nil && excepted == prevExcepted {
			kept := slices.DeleteFunc(slices.Clone(changes), func(c model.HistoryChange) bool {
				return c.Type == model.EventExceptionAdd || c.Type == model.EventExceptionRev || c.Type == model.EventExceptionExp
			})
			if len(kept) < len(changes) {
				out, _ := json.Marshal(nonNil(kept))
				b.Queue(`UPDATE history SET changes = $3 WHERE env = $1 AND taken_at = $2`, env, at, out)
			}
		}
		prevExcepted = excepted
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if b.Len() > 0 {
		if err := s.pool.SendBatch(ctx, b).Close(); err != nil {
			return 0, err
		}
	}
	return b.Len(), nil
}

// HistoryStart is when the oldest point was taken (zero when there is none).
func (s *Store) HistoryStart(ctx context.Context) (time.Time, error) {
	var t *time.Time
	err := s.pool.QueryRow(ctx, `SELECT min(taken_at) FROM history`).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}

// FactSpan is a history fact and when it held: Until is zero while it still does.
type FactSpan struct {
	Fact         model.HistoryFact
	Since, Until time.Time
}

const factCols = `env, cluster, namespace, kind, name, vuln_id, pkg_name, pkg_type, severity, kev, has_fix, suspect, covered, exposure`

// scanFact reads factCols, then extra columns into extra.
func scanFact(row pgx.Row, f *model.HistoryFact, extra ...any) error {
	var sev string
	err := row.Scan(append([]any{&f.Env, &f.Cluster, &f.Namespace, &f.Kind, &f.Name, &f.VulnID, &f.PkgName, &f.PkgType,
		&sev, &f.KEV, &f.HasFix, &f.Suspect, &f.Covered, &f.Exposure}, extra...)...)
	f.Severity = model.Severity(sev)
	return err
}

// OpenHistoryFacts returns the facts that still hold, with their row ids. A
// second open row of the same fact comes back in duplicates, to be closed.
func (s *Store) OpenHistoryFacts(ctx context.Context) (open map[model.HistoryFact]int64, duplicates []int64, err error) {
	rows, err := s.pool.Query(ctx, `SELECT `+factCols+`, id FROM history_facts WHERE until IS NULL ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	open = map[model.HistoryFact]int64{}
	for rows.Next() {
		var f model.HistoryFact
		var id int64
		if err := scanFact(rows, &f, &id); err != nil {
			return nil, nil, err
		}
		if _, dup := open[f]; dup {
			duplicates = append(duplicates, id)
			continue
		}
		open[f] = id
	}
	return open, duplicates, rows.Err()
}

// UpdateHistoryFacts closes the rows closed and opens a row for each fact of
// opened, both at at, in one transaction. It returns the new rows' ids, in the
// order of opened.
func (s *Store) UpdateHistoryFacts(ctx context.Context, closed []int64, opened []model.HistoryFact, at time.Time) ([]int64, error) {
	ids := make([]int64, len(opened))
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if len(closed) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE history_facts SET until = $2 WHERE id = ANY($1) AND until IS NULL`, closed, at); err != nil {
				return err
			}
		}
		if len(opened) == 0 {
			return nil
		}
		b := &pgx.Batch{}
		for _, f := range opened {
			b.Queue(`INSERT INTO history_facts (`+factCols+`, since)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id`,
				f.Env, f.Cluster, f.Namespace, f.Kind, f.Name, f.VulnID, f.PkgName, f.PkgType,
				string(f.Severity), f.KEV, f.HasFix, f.Suspect, f.Covered, f.Exposure, at)
		}
		br := tx.SendBatch(ctx, b)
		for i := range opened {
			if err := br.QueryRow().Scan(&ids[i]); err != nil {
				br.Close()
				return err
			}
		}
		return br.Close()
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// HistoryFactsSince returns the facts of env that held at some point after
// since, by their start, and when the env's facts begin (zero when it has none).
func (s *Store) HistoryFactsSince(ctx context.Context, env string, since time.Time) ([]FactSpan, time.Time, error) {
	var first *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT min(since) FROM history_facts WHERE env = $1`, env).Scan(&first); err != nil || first == nil {
		return nil, time.Time{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+factCols+`, since, until FROM history_facts
		WHERE env = $1 AND (until IS NULL OR until > $2) ORDER BY since, id`, env, since)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()
	var out []FactSpan
	for rows.Next() {
		var sp FactSpan
		var until *time.Time
		if err := scanFact(rows, &sp.Fact, &sp.Since, &until); err != nil {
			return nil, time.Time{}, err
		}
		if until != nil {
			sp.Until = *until
		}
		out = append(out, sp)
	}
	return out, *first, rows.Err()
}

func (s *Store) SetState(ctx context.Context, key, value string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO state (key, value, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()`, key, value)
	if err == nil {
		s.changed()
	}
	return err
}

func (s *Store) State(ctx context.Context, key string) (string, error) {
	var v string
	err := s.pool.QueryRow(ctx, `SELECT value FROM state WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// Secret returns the secret called name, created from fresh random bytes on
// first use: the same value across restarts, without configuration.
func (s *Store) Secret(ctx context.Context, name string, size int) ([]byte, error) {
	fresh := make([]byte, size)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO secrets (name, value) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, name, fresh); err != nil {
		return nil, err
	}
	var v []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM secrets WHERE name = $1`, name).Scan(&v)
	return v, err
}

func (s *Store) SetStateTime(ctx context.Context, key string, t time.Time) error {
	return s.SetState(ctx, key, t.UTC().Format(time.RFC3339))
}

func (s *Store) StateTime(ctx context.Context, key string) (time.Time, error) {
	v, err := s.State(ctx, key)
	if err != nil || v == "" {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, v)
}

// ---- read model -------------------------------------------------------------

// Dataset loads everything the read API needs in one consistent snapshot.
func (s *Store) Dataset(ctx context.Context) (*model.Dataset, error) {
	ds := &model.Dataset{
		Findings:    map[string][]model.FindingRow{},
		Vulns:       map[string]model.Vuln{},
		ImageStatus: map[string]string{},
		ImageErrors: map[string]model.ImageError{},
		State:       map[string]string{},
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read-only

	rows, err := tx.Query(ctx, `SELECT `+containerCols+` FROM containers c JOIN images i USING (digest)`)
	if err != nil {
		return nil, err
	}
	if ds.Containers, err = scanContainers(rows); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT digest, vuln_id, pkg_name, pkg_version, pkg_type, purl, fixed_in, first_seen, source, location
		FROM findings WHERE digest IN (SELECT digest FROM containers)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var digest string
		var f model.FindingRow
		if err := rows.Scan(&digest, &f.VulnID, &f.Pkg.Name, &f.Pkg.Version, &f.Pkg.Type, &f.Pkg.PURL, &f.FixedIn, &f.FirstSeen, &f.Source, &f.Location); err != nil {
			return nil, err
		}
		ds.Findings[digest] = append(ds.Findings[digest], f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT id, aliases, severity, cvss, epss, epss_percentile, kev, kev_added, description, url
		FROM vulns WHERE id IN (SELECT vuln_id FROM findings WHERE digest IN (SELECT digest FROM containers))`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v model.Vuln
		var sev string
		var kev bool
		if err := rows.Scan(&v.ID, &v.Aliases, &sev, &v.CVSS, &v.EPSS, &v.EPSSPercentile, &kev, &v.KEVAddedAt, &v.Description, &v.URL); err != nil {
			return nil, err
		}
		v.Severity, v.KEV = model.Severity(sev), &kev
		ds.Vulns[v.ID] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT digest, status, COALESCE(error, ''), attempts FROM images WHERE digest IN (SELECT digest FROM containers)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d, st, msg string
		var attempts int
		if err := rows.Scan(&d, &st, &msg, &attempts); err != nil {
			return nil, err
		}
		ds.ImageStatus[d] = st
		if msg != "" {
			ds.ImageErrors[d] = model.ImageError{Error: msg, Attempts: attempts}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT `+exceptionCols+` FROM exceptions WHERE revoked_at IS NULL AND expires_at > now()`)
	if err != nil {
		return nil, err
	}
	if ds.Exceptions, err = scanExceptions(rows); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT key, value FROM state`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		ds.State[k] = v
	}
	return ds, rows.Err()
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ---- exceptions -------------------------------------------------------------

const exceptionCols = `id, vuln_id, pkg_name, namespace, workload, justification, statement, author,
	created_at, expires_at, revoked_at, revoked_by`

func scanExceptions(rows pgx.Rows) ([]model.Exception, error) {
	now := time.Now()
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.Exception, error) {
		var e model.Exception
		err := row.Scan(&e.ID, &e.VulnID, &e.Package, &e.Namespace, &e.Workload, &e.Justification, &e.Statement,
			&e.Author, &e.CreatedAt, &e.ExpiresAt, &e.RevokedAt, &e.RevokedBy)
		e.State = e.StateAt(now)
		return e, err
	})
}

// Exceptions lists every exception, active and expiring first, then the most
// recently expired or revoked.
func (s *Store) Exceptions(ctx context.Context) ([]model.Exception, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+exceptionCols+` FROM exceptions
		ORDER BY (revoked_at IS NULL AND expires_at > now()) DESC,
		         CASE WHEN revoked_at IS NULL AND expires_at > now() THEN expires_at END ASC,
		         COALESCE(revoked_at, expires_at) DESC`)
	if err != nil {
		return nil, err
	}
	return scanExceptions(rows)
}

func (s *Store) AddException(ctx context.Context, e model.Exception) (model.Exception, error) {
	rows, err := s.pool.Query(ctx, `INSERT INTO exceptions (vuln_id, pkg_name, namespace, workload, justification, statement, author, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING `+exceptionCols,
		e.VulnID, e.Package, e.Namespace, e.Workload, e.Justification, e.Statement, e.Author, e.ExpiresAt)
	if err != nil {
		return e, err
	}
	out, err := scanExceptions(rows)
	if err != nil || len(out) == 0 {
		return e, err
	}
	s.changed()
	return out[0], nil
}

// RevokeException ends an exception now. ok is false if it does not exist or
// was already revoked.
func (s *Store) RevokeException(ctx context.Context, id int64, by string) (model.Exception, bool, error) {
	rows, err := s.pool.Query(ctx, `UPDATE exceptions SET revoked_at = now(), revoked_by = $2
		WHERE id = $1 AND revoked_at IS NULL RETURNING `+exceptionCols, id, by)
	if err != nil {
		return model.Exception{}, false, err
	}
	out, err := scanExceptions(rows)
	if err != nil || len(out) == 0 {
		return model.Exception{}, false, err
	}
	s.changed()
	return out[0], true, nil
}

// ExpiredUnnotified returns the exceptions that expired since the last call,
// and marks them as notified.
func (s *Store) ExpiredUnnotified(ctx context.Context) ([]model.Exception, error) {
	rows, err := s.pool.Query(ctx, `UPDATE exceptions SET expiry_notified = true
		WHERE NOT expiry_notified AND revoked_at IS NULL AND expires_at <= now() RETURNING `+exceptionCols)
	if err != nil {
		return nil, err
	}
	out, err := scanExceptions(rows)
	if err == nil && len(out) > 0 {
		s.changed()
	}
	return out, err
}
