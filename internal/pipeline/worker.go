package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/n0cl0ud/paindash/internal/inventory"
	"github.com/n0cl0ud/paindash/internal/live"
	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/scan"
	"github.com/n0cl0ud/paindash/internal/store"
)

// Worker scans new images and rematches every stored SBOM when the
// vulnerability DB is refreshed, so new CVEs show up without any redeploy.
type Worker struct {
	Scanner      scan.Scanner
	Store        *store.Store
	Hub          *live.Hub
	Emit         *Emitter
	Enricher     *Enricher // nil when enrichment is disabled (demo)
	Concurrency  int
	RematchEvery time.Duration
	PriorityEnv  string
	MaxAttempts  int
	// ProgressEvery: during the (silent) initial scan, how often each env gets
	// a progress event in its live feed.
	ProgressEvery time.Duration
	Log           *slog.Logger

	once    sync.Once
	wake    chan struct{}
	initial sync.Mutex
}

func (w *Worker) wakeCh() chan struct{} {
	w.once.Do(func() { w.wake = make(chan struct{}, 1) })
	return w.wake
}

// Wake makes idle scan loops look for pending images right away.
func (w *Worker) Wake() {
	select {
	case w.wakeCh() <- struct{}{}:
	default:
	}
}

func (w *Worker) Run(ctx context.Context) {
	if err := w.Store.ResetScanning(ctx); err != nil {
		w.Log.Error("reset scanning images", "err", err)
	}
	// Matching needs a vulnerability DB: on a fresh pod it must be downloaded
	// before any scan, otherwise every image would fail.
	for {
		err := w.refreshDB(ctx)
		if err == nil {
			break
		}
		w.Log.Warn("vulnerability DB not ready, scans on hold", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
	w.applyMatchRules(ctx)
	w.retryFailed(ctx)
	var wg sync.WaitGroup
	for range max(w.Concurrency, 1) {
		wg.Add(1)
		go func() { defer wg.Done(); w.scanLoop(ctx) }()
	}
	wg.Add(3)
	go func() { defer wg.Done(); w.rematchLoop(ctx) }()
	go func() { defer wg.Done(); w.initialProgressLoop(ctx) }()
	go func() { defer wg.Done(); w.backfillProvenance(ctx) }()
	wg.Wait()
}

// backfillProvenance reads the labels of the images scanned before they were
// recorded, from their stored SBOM.
func (w *Worker) backfillProvenance(ctx context.Context) {
	digests, err := w.Store.ProvenanceMissing(ctx)
	if err != nil {
		w.Log.Warn("provenance backfill", "err", err)
		return
	}
	provs := map[string]store.Provenance{}
	for _, d := range digests {
		sbom, err := w.Store.SBOM(ctx, d)
		if err != nil {
			w.Log.Warn("provenance backfill: load sbom", "digest", d, "err", err)
			continue
		}
		src, rev := scan.Provenance(sbom)
		provs[d] = store.Provenance{Source: src, Revision: rev}
	}
	if len(provs) == 0 {
		return
	}
	if err := w.Store.SetProvenance(ctx, provs); err != nil {
		w.Log.Warn("provenance backfill", "err", err)
		return
	}
	w.Log.Info("provenance backfilled", "images", len(provs))
	w.Hub.Invalidate(model.AllEnvs)
}

func (w *Worker) scanLoop(ctx context.Context) {
	for ctx.Err() == nil {
		digest, ref, quiet, ok, err := w.Store.ClaimImage(ctx, w.PriorityEnv)
		if err != nil {
			w.Log.Error("claim image", "err", err)
		}
		if !ok {
			select {
			case <-ctx.Done():
			case <-w.wakeCh():
			case <-time.After(30 * time.Second):
			}
			continue
		}
		w.scanImage(ctx, digest, ref, quiet)
	}
}

func (w *Worker) scanImage(ctx context.Context, digest, ref string, quiet bool) {
	start := time.Now()
	log := w.Log.With("ref", ref)
	sbom, err := w.Scanner.SBOM(ctx, ref)
	var res scan.Result
	if err == nil {
		res, err = w.Scanner.Match(ctx, sbom)
	}
	if err != nil {
		if ctx.Err() != nil {
			return // shutting down: ResetScanning picks it up on restart
		}
		final, ferr := w.Store.FailScan(ctx, digest, err.Error(), w.MaxAttempts)
		if ferr != nil {
			log.Error("record scan failure", "err", ferr)
		}
		log.Warn("scan failed", "err", err, "final", final)
		if final && !quiet {
			w.announceFailure(ctx, digest, ref)
		}
		w.Hub.Invalidate(model.AllEnvs)
		return
	}
	src, rev := scan.Provenance(sbom)
	if err := w.Store.SetProvenance(ctx, map[string]store.Provenance{digest: {Source: src, Revision: rev}}); err != nil {
		log.Warn("save provenance", "err", err)
	}
	if _, err := w.Store.SaveMatches(ctx, digest, sbom, res.Matches, res.DBBuilt); err != nil {
		log.Error("save scan", "err", err)
		return
	}
	if w.Enricher != nil {
		w.Enricher.Apply(ctx, vulnIDs(res.Matches))
	}
	log.Info("image scanned", "matches", len(res.Matches), "took", time.Since(start).Round(time.Millisecond).String())
	w.Hub.Invalidate(model.AllEnvs)
	if quiet {
		w.checkInitialDone(ctx)
		return
	}
	w.announceScan(ctx, digest)
}

func (w *Worker) announceScan(ctx context.Context, digest string) {
	containers, err := w.Store.ContainersForDigest(ctx, digest)
	if err != nil {
		return
	}
	vulns, err := w.Store.ImageVulns(ctx, digest)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, c := range containers {
		if seen[c.Env+c.WorkloadRef.Key()] {
			continue
		}
		seen[c.Env+c.WorkloadRef.Key()] = true
		ref, image := c.WorkloadRef, c.Image
		ev := model.LiveEvent{Env: c.Env, Cluster: c.Cluster, Type: model.EventScanCompleted, Workload: &ref, Image: &image}
		name := fmt.Sprintf("%s/%s (%s)", c.Namespace, c.Name, inventory.Tag(c.Image))
		oldDigest, _, hadPrevious, _ := w.Store.PreviousImage(ctx, c)
		add, rem, compared := []model.VulnRef(nil), []model.VulnRef(nil), false
		if hadPrevious {
			add, rem, compared, _ = w.Store.CompareImages(ctx, oldDigest, digest)
		}
		if compared {
			ev.Title = fmt.Sprintf("%s scanned: +%d / −%d vulnerabilities vs previous version", name, len(add), len(rem))
			ev.Severity = maxSeverity(add)
			ev.Delta = &model.Delta{Added: len(add), Removed: len(rem), KEV: countKEV(add)}
		} else {
			ev.Title = fmt.Sprintf("%s scanned: %s", name, severityPhrase(vulns))
			ev.Severity = maxSeverity(vulns)
			ev.Delta = &model.Delta{Added: len(vulns), KEV: countKEV(vulns)}
		}
		w.Emit.Emit(ctx, ev)
	}
}

func (w *Worker) announceFailure(ctx context.Context, digest, ref string) {
	containers, err := w.Store.ContainersForDigest(ctx, digest)
	if err != nil {
		return
	}
	for env, cs := range byEnv(containers) {
		image := cs[0].Image
		w.Emit.Emit(ctx, model.LiveEvent{
			Env: env, Cluster: cs[0].Cluster, Type: model.EventScanFailed, Image: &image,
			Workload: workloadIfSingle(workloads(cs)),
			Title:    fmt.Sprintf("Scan of %s failed after %d attempts", inventory.Tag(ref), w.MaxAttempts),
		})
	}
}

// checkInitialDone announces once that the images of the initial inventory
// are all scanned.
func (w *Worker) checkInitialDone(ctx context.Context) {
	w.initial.Lock()
	defer w.initial.Unlock()
	if done, _ := w.Store.State(ctx, store.StateInitialScan); done != "" {
		return
	}
	if n, err := w.Store.PendingQuiet(ctx); err != nil || n > 0 {
		return
	}
	if err := w.Store.SetStateTime(ctx, store.StateInitialScan, time.Now()); err != nil {
		return
	}
	w.Emit.Emit(ctx, model.LiveEvent{Env: model.AllEnvs, Type: model.EventScanCompleted, Title: "Initial scan complete: every running image is scanned"})
}

// retryEvery spaces the retries of failed scans, whatever the DB check
// cadence: an image that keeps failing would otherwise be announced each check.
const retryEvery = 6 * time.Hour

func (w *Worker) rematchLoop(ctx context.Context) {
	retried := time.Now() // Run retried at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.RematchEvery):
		}
		if err := w.refreshDB(ctx); err != nil && ctx.Err() == nil {
			w.Log.Warn("vulnerability DB refresh failed", "err", err)
		}
		if time.Since(retried) >= retryEvery {
			w.retryFailed(ctx)
			retried = time.Now()
		}
	}
}

// retryFailed gives failed images another chance (at startup and every
// retryEvery), so that fixed causes heal on their own.
func (w *Worker) retryFailed(ctx context.Context) {
	n, err := w.Store.RetryFailed(ctx)
	switch {
	case err != nil:
		w.Log.Warn("retry failed images", "err", err)
	case n > 0:
		w.Log.Info("retrying failed images", "images", n)
		w.Wake()
	}
}

func (w *Worker) refreshDB(ctx context.Context) error {
	built, err := w.Scanner.UpdateDB(ctx)
	if err != nil {
		return err
	}
	if err := w.Store.SetStateTime(ctx, store.StateVulnDBChecked, time.Now()); err != nil {
		return err
	}
	last, err := w.Store.StateTime(ctx, store.StateVulnDBBuilt)
	if err != nil || built.IsZero() || built.Equal(last) {
		return err
	}
	if err := w.Store.SetStateTime(ctx, store.StateVulnDBBuilt, built); err != nil {
		return err
	}
	w.Hub.Invalidate(model.AllEnvs)
	if last.IsZero() {
		return nil // first DB seen: images get scanned against it anyway
	}
	return w.rematch(ctx, built, false)
}

// applyMatchRules rematches the stored SBOMs once when the pruning/matching
// rules of this version differ from those that produced the stored findings
// (e.g. false positives fixed in a new release).
func (w *Worker) applyMatchRules(ctx context.Context) {
	if v, err := w.Store.State(ctx, store.StateMatchRules); err != nil || v == scan.RulesVersion {
		return
	}
	built, err := w.Store.StateTime(ctx, store.StateVulnDBBuilt)
	if err == nil {
		err = w.rematch(ctx, built, true)
	}
	if err != nil {
		w.Log.Warn("rematch with new rules", "err", err)
		return
	}
	_ = w.Store.SetState(ctx, store.StateMatchRules, scan.RulesVersion)
}

// rematch matches every stored SBOM again: after a DB update, or when the
// matching rules changed (rules=true).
func (w *Worker) rematch(ctx context.Context, built time.Time, rules bool) error {
	start := time.Now()
	digests, err := w.Store.RematchCandidates(ctx)
	if err != nil || len(digests) == 0 {
		return err
	}
	var mu sync.Mutex
	changes := map[string]store.ScanChange{}
	sem := make(chan struct{}, max(w.Concurrency, 1))
	var wg sync.WaitGroup
	for _, d := range digests {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			sbom, err := w.Store.SBOM(ctx, d)
			if err != nil {
				w.Log.Warn("rematch: load sbom", "digest", d, "err", err)
				return
			}
			res, err := w.Scanner.Match(ctx, sbom)
			if err != nil {
				w.Log.Warn("rematch", "digest", d, "err", err)
				return
			}
			ch, err := w.Store.SaveMatches(ctx, d, nil, res.Matches, built)
			if err != nil {
				w.Log.Warn("rematch: save", "digest", d, "err", err)
				return
			}
			mu.Lock()
			changes[d] = ch
			mu.Unlock()
		}()
	}
	wg.Wait()

	var newIDs []string
	newKEV := map[string]bool{}
	for _, ch := range changes {
		for _, v := range ch.Added {
			newIDs = append(newIDs, v.ID)
		}
		for _, id := range ch.NewKEV {
			newKEV[id] = true
		}
	}
	if w.Enricher != nil {
		w.Enricher.Apply(ctx, newIDs)
	}
	refs, _ := w.Store.VulnRefs(ctx, newIDs) // KEV flags after enrichment

	containers, err := w.Store.Containers(ctx)
	if err != nil {
		return err
	}
	for env, cs := range byEnv(containers) {
		added, removed := map[string]model.VulnRef{}, map[string]model.VulnRef{}
		touched := map[string]bool{}
		for _, c := range cs {
			ch := changes[c.Digest]
			for _, v := range ch.Added {
				if r, ok := refs[v.ID]; ok {
					v = r
				}
				added[v.ID] = v
				touched[c.WorkloadRef.Key()] = true
			}
			for _, v := range ch.Removed {
				removed[v.ID] = v
			}
		}
		addList := make([]model.VulnRef, 0, len(added))
		for _, v := range added {
			addList = append(addList, v)
		}
		switch {
		case len(added) > 0:
			w.Emit.Emit(ctx, model.LiveEvent{
				Env: env, Cluster: cs[0].Cluster, Type: model.EventVulnsNew,
				Title: fmt.Sprintf("%s: %s on %s (%s)", cond(rules, "Matching rules updated", "New CVEs published"),
					plural(len(added), "vulnerability", "vulnerabilities"), plural(len(touched), "workload", "workloads"), severityPhrase(addList)),
				Severity: maxSeverity(addList),
				Delta:    &model.Delta{Added: len(added), Removed: len(removed), KEV: countKEV(addList)},
			})
		case len(removed) > 0:
			w.Emit.Emit(ctx, model.LiveEvent{
				Env: env, Cluster: cs[0].Cluster, Type: model.EventVulnsFixed,
				Title: fmt.Sprintf("%s: %s no longer apply", cond(rules, "Matching rules updated (false positives removed)", "CVE DB updated"),
					plural(len(removed), "vulnerability", "vulnerabilities")),
				Delta: &model.Delta{Removed: len(removed)},
			})
		}
	}
	for id := range newKEV {
		announceKEV(ctx, w.Store, w.Emit, id)
	}
	if rules {
		w.Emit.Emit(ctx, model.LiveEvent{
			Env: model.AllEnvs, Type: model.EventScanCompleted,
			Title: fmt.Sprintf("Matching rules updated: %s rematched", plural(len(changes), "image", "images")),
		})
	} else {
		w.Emit.Emit(ctx, model.LiveEvent{
			Env: model.AllEnvs, Type: model.EventDBUpdated,
			Title: fmt.Sprintf("Vulnerability DB updated (built %s UTC), %s rematched", built.UTC().Format("Jan 2 15:04"), plural(len(changes), "image", "images")),
		})
	}
	w.Log.Info("rematch done", "images", len(changes), "took", time.Since(start).Round(time.Second).String())
	return nil
}

func vulnIDs(matches []model.Match) []string {
	seen := map[string]bool{}
	var ids []string
	for _, m := range matches {
		if !seen[m.Vuln.ID] {
			seen[m.Vuln.ID] = true
			ids = append(ids, m.Vuln.ID)
		}
	}
	return ids
}
