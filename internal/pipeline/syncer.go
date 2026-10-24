package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/inventory"
	"github.com/n0cl0ud/paindash/internal/live"
	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
)

// Syncer keeps the stored inventory in line with what runs, and announces
// deployments and removals.
type Syncer struct {
	Source   inventory.Source
	Store    *store.Store
	Hub      *live.Hub
	Emit     *Emitter
	Interval time.Duration
	// Grace keeps the rows of a cluster absent from a snapshot (scrape gap,
	// store restart) before treating its workloads as removed.
	Grace       time.Duration
	OnNewImages func()
	// Retention: images that stopped running, and events, are pruned after it.
	Retention time.Duration
	Log       *slog.Logger
}

func (s *Syncer) Run(ctx context.Context) {
	var lastPrune time.Time
	for {
		start := time.Now()
		if err := s.Sync(ctx); err != nil {
			s.Log.Warn("inventory sync failed", "source", s.Source.Name(), "err", err)
		} else {
			s.Log.Debug("inventory synced", "took", time.Since(start).String())
		}
		s.expireExceptions(ctx)
		if s.Retention > 0 && time.Since(lastPrune) > time.Hour {
			lastPrune = time.Now()
			if n, err := s.Store.Prune(ctx, s.Retention); err != nil {
				s.Log.Warn("prune failed", "err", err)
			} else if n > 0 {
				s.Log.Info("pruned retired images", "images", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.Interval):
		}
	}
}

// expireExceptions announces the exceptions that just expired: their
// findings are back in the lists.
func (s *Syncer) expireExceptions(ctx context.Context) {
	expired, err := s.Store.ExpiredUnnotified(ctx)
	if err != nil {
		s.Log.Warn("expired exceptions", "err", err)
		return
	}
	for _, e := range expired {
		where := ""
		if e.Namespace != "" {
			where = " (" + strings.TrimSuffix(e.Namespace+"/"+e.Workload, "/") + ")"
		}
		// In the feed (and history) of the envs it covered, or of every env if none.
		envs, err := s.Store.ExceptionEnvs(ctx, e)
		if err != nil {
			s.Log.Warn("exception envs", "err", err)
		}
		if len(envs) == 0 {
			envs = []string{model.AllEnvs}
		}
		for _, env := range envs {
			s.Emit.Emit(ctx, model.LiveEvent{
				Env: env, Type: model.EventExceptionExp,
				Title: fmt.Sprintf("Exception expired: %s in %s%s is back in the lists", e.VulnID, e.Package, where),
			})
		}
	}
	if len(expired) > 0 {
		s.Hub.Invalidate(model.AllEnvs)
	}
}

func (s *Syncer) Sync(ctx context.Context) error {
	snapshot, err := s.Source.Snapshot(ctx)
	if err != nil {
		return err
	}
	prevList, err := s.Store.Containers(ctx)
	if err != nil {
		return err
	}
	hasHistory, err := s.Store.HasHistory(ctx)
	if err != nil {
		return err
	}

	present := map[string]bool{}
	cur := map[string]model.Container{}
	for _, c := range snapshot {
		present[c.Cluster] = true
		cur[c.Key()] = c
	}
	prev := map[string]model.Container{}
	for _, c := range prevList {
		prev[c.Key()] = c
		if !present[c.Cluster] && time.Since(c.LastSeen) < s.Grace {
			cur[c.Key()] = c
		}
	}

	var added, removed, exposed []model.Container
	for k, c := range cur {
		p, ok := prev[k]
		switch {
		case !ok:
			added = append(added, c)
		case present[c.Cluster] && p.Exposure != c.Exposure:
			exposed = append(exposed, c)
		}
	}
	for k, c := range prev {
		if _, ok := cur[k]; !ok {
			removed = append(removed, c)
		}
	}
	sortContainers(added)
	sortContainers(removed)

	clusters := make([]string, 0, len(present))
	for c := range present {
		clusters = append(clusters, c)
	}
	if err := s.Store.ApplyInventory(ctx, store.InventoryChange{
		Added: added, Removed: removed, Exposed: exposed, Clusters: clusters, Quiet: !hasHistory,
	}); err != nil {
		return err
	}
	if src, ok := s.Source.(interface{ ExposureAvailable() bool }); ok {
		v := "0"
		if src.ExposureAvailable() {
			v = "1"
		}
		if cur, _ := s.Store.State(ctx, store.StateExposure); cur != v {
			_ = s.Store.SetState(ctx, store.StateExposure, v)
		}
	}
	if len(exposed) > 0 {
		s.Hub.Invalidate(model.AllEnvs)
	}
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	s.Log.Info("inventory changed", "added", len(added), "removed", len(removed))

	if !hasHistory {
		s.announceInitial(ctx, snapshot)
	} else {
		s.announce(ctx, prev, cur, added, removed)
	}
	if len(added) > 0 && s.OnNewImages != nil {
		s.OnNewImages()
	}
	envs := map[string]bool{}
	for _, c := range append(added, removed...) {
		envs[c.Env] = true
	}
	for e := range envs {
		s.Hub.Invalidate(e)
	}
	return nil
}

func (s *Syncer) announceInitial(ctx context.Context, snapshot []model.Container) {
	for env, cs := range byEnv(snapshot) {
		digests := map[string]bool{}
		for _, c := range cs {
			digests[c.Digest] = true
		}
		s.Emit.Emit(ctx, model.LiveEvent{
			Env:     env,
			Cluster: cs[0].Cluster,
			Type:    model.EventDeployed,
			Title: fmt.Sprintf("Initial inventory: %s, %s to scan",
				plural(len(workloads(cs)), "workload", "workloads"), plural(len(digests), "image", "images")),
		})
	}
}

func (s *Syncer) announce(ctx context.Context, prev, cur map[string]model.Container, added, removed []model.Container) {
	prevWorkloads, curWorkloads := map[string]bool{}, map[string]bool{}
	for _, c := range prev {
		prevWorkloads[c.WorkloadRef.Key()] = true
	}
	for _, c := range cur {
		curWorkloads[c.WorkloadRef.Key()] = true
	}

	// One event per workload, about its first changed container.
	done := map[string]bool{}
	for _, c := range added {
		wk := c.WorkloadRef.Key()
		if done[wk] {
			continue
		}
		done[wk] = true
		if ev, ok := s.deployedEvent(ctx, c, prevWorkloads[wk]); ok {
			s.Emit.Emit(ctx, ev)
		}
	}

	done = map[string]bool{}
	for _, c := range removed {
		wk := c.WorkloadRef.Key()
		if done[wk] || curWorkloads[wk] || isBatch(c.Kind) {
			continue
		}
		done[wk] = true
		ref := c.WorkloadRef
		s.Emit.Emit(ctx, model.LiveEvent{
			Env: c.Env, Cluster: c.Cluster, Type: model.EventRemoved, Workload: &ref,
			Title: fmt.Sprintf("%s %s/%s no longer running", c.Kind, c.Namespace, c.Name),
		})
	}
}

func (s *Syncer) deployedEvent(ctx context.Context, c model.Container, existed bool) (model.LiveEvent, bool) {
	ref, image := c.WorkloadRef, c.Image
	ev := model.LiveEvent{Env: c.Env, Cluster: c.Cluster, Type: model.EventDeployed, Workload: &ref, Image: &image}
	name := c.Namespace + "/" + c.Name

	scanned, err := s.Store.ImageScanned(ctx, c.Digest)
	if err != nil {
		s.Log.Warn("deployed event", "err", err)
	}
	oldDigest, oldImage, hadPrevious, err := s.Store.PreviousImage(ctx, c)
	if err != nil {
		s.Log.Warn("deployed event", "err", err)
	}

	if !existed {
		// Batch workloads come and go with each run: only a new image is news.
		if isBatch(c.Kind) {
			if again, _ := s.Store.DeployedBefore(ctx, c); again {
				return ev, false
			}
		}
		ev.Title = fmt.Sprintf("%s %s deployed (%s)", c.Kind, name, inventory.Tag(c.Image))
		if scanned {
			if vulns, err := s.Store.ImageVulns(ctx, c.Digest); err == nil {
				ev.Severity = maxSeverity(vulns)
				ev.Delta = &model.Delta{Added: len(vulns), KEV: countKEV(vulns)}
			}
		}
	} else {
		from := "?"
		if hadPrevious {
			from = inventory.Tag(oldImage)
		}
		ev.Title = fmt.Sprintf("%s: %s → %s", name, from, inventory.Tag(c.Image))
		if hadPrevious && scanned {
			if add, rem, ok, err := s.Store.CompareImages(ctx, oldDigest, c.Digest); err == nil && ok {
				ev.Severity = maxSeverity(add)
				ev.Delta = &model.Delta{Added: len(add), Removed: len(rem), KEV: countKEV(add)}
			}
		}
	}
	if !scanned {
		ev.Title += " · scanning"
	}
	return ev, true
}

func isBatch(kind string) bool { return kind == "Job" || kind == "CronJob" }

func sortContainers(cs []model.Container) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Key() < cs[j].Key() })
}
