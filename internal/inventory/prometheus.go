// Package inventory lists the containers running in the clusters.
//
// The default source reads kube-state-metrics series through a Prometheus-
// compatible API (Prometheus, Thanos, Mimir...): it needs no access to the
// clusters, and image_id carries the digest actually pulled by the kubelet,
// which is what we want to scan (tags are mutable).
package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

type Source interface {
	Name() string
	Snapshot(ctx context.Context) ([]model.Container, error)
}

// Prometheus reads kube-state-metrics series. Several clusters and envs are
// told apart by series labels (EnvLabel, ClusterLabel), as a Thanos or Mimir
// in front of per-cluster Prometheus servers adds them; a single Prometheus
// without such labels uses DefaultEnv and DefaultCluster.
type Prometheus struct {
	URL            string
	Envs           []string // env label values to keep; empty keeps all
	EnvLabel       string   // default "env"
	ClusterLabel   string   // default "cluster"
	DefaultEnv     string   // env of series without EnvLabel; set, no env filter applies
	DefaultCluster string   // cluster of series without ClusterLabel (default "default")
	// PublicEntrypoints are the Traefik entrypoints reachable from the
	// internet (default "web" and "websecure"). Entrypoints named *-internal
	// or *-int are internal; any other one is treated as internet-facing (and
	// logged) rather than silently understated.
	PublicEntrypoints []string
	// IngressClasses maps Ingress classes to an exposure ("internet" or
	// "internal"). Unlisted classes are internal when their name contains
	// "internal" or "private", internet-facing otherwise.
	IngressClasses map[string]string
	Client         *http.Client
	Log            *slog.Logger

	exposureAvailable bool
	unknown           map[string]bool // unclassified entrypoints already logged
}

// ExposureAvailable reports whether the last snapshot found routing metrics
// (Ingress, IngressRoute or LoadBalancer), i.e. whether "none" can be trusted.
func (t *Prometheus) ExposureAvailable() bool { return t.exposureAvailable }

func (t *Prometheus) Name() string { return "prometheus" }

func (t *Prometheus) Snapshot(ctx context.Context) ([]model.Container, error) {
	sel := ""
	if len(t.Envs) > 0 && t.DefaultEnv == "" {
		quoted := make([]string, len(t.Envs))
		for i, e := range t.Envs {
			quoted[i] = regexp.QuoteMeta(e)
		}
		sel = fmt.Sprintf(`{%s=~%q}`, t.envLabel(), strings.Join(quoted, "|"))
	}
	// Init containers run images too (often small tools such as busybox that
	// never show up as regular containers): they are part of the inventory.
	var series [5][]map[string]string
	for i, metric := range []string{"kube_pod_container_info", "kube_pod_init_container_info", "kube_pod_owner", "kube_replicaset_owner", "kube_job_owner"} {
		res, err := t.query(ctx, metric+sel)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", metric, err)
		}
		series[i] = res
	}
	exposure, err := t.exposure(ctx, sel)
	if err != nil {
		return nil, err
	}
	cs := resolve(append(series[0], series[1]...), series[2], series[3], series[4], t.envLabel(), t.clusterLabel())
	for i := range cs {
		e := model.ExposureNone
		for _, pod := range cs[i].pods { // replicas could differ during a rollout
			e = model.WiderExposure(e, exposure[pod])
		}
		cs[i].Exposure = e
	}
	return stripPodKeys(cs), nil
}

// exposure maps each pod to its exposure: Ingresses (by class), Traefik
// IngressRoute entrypoints and LoadBalancer Services give a level per Service,
// endpoints give the pod IPs behind each Service, kube_pod_info maps the IPs
// back to pods.
func (t *Prometheus) exposure(ctx context.Context, sel string) (map[objKey]string, error) {
	cl := t.clusterLabel()
	queries := []string{"kube_service_status_load_balancer_ingress", "kube_endpoint_address", "kube_pod_info", "kube_ingress_info", "kube_ingress_path"}
	var entrypoints, routes []map[string]string
	for _, kind := range []string{"ingressroute", "ingressroutetcp", "ingressrouteudp"} {
		queries = append(queries, "kube_traefik_"+kind+"_entrypoint", "kube_traefik_"+kind+"_service")
	}
	series := map[string][]map[string]string{}
	for _, metric := range queries {
		res, err := t.query(ctx, metric+sel)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", metric, err)
		}
		// HTTP and TCP routes can share a name: key them by kind too.
		kind := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(metric, "kube_traefik_"), "_entrypoint"), "_service")
		for _, m := range res {
			m["ingressroute"] = kind + "/" + m["ingressroute"]
		}
		switch {
		case strings.HasSuffix(metric, "_entrypoint"):
			entrypoints = append(entrypoints, res...)
		case strings.HasSuffix(metric, "_service") && strings.HasPrefix(metric, "kube_traefik_"):
			routes = append(routes, res...)
		default:
			series[metric] = res
		}
	}
	lbs, endpoints, pods := series[queries[0]], series[queries[1]], series[queries[2]]
	ingresses, paths := series[queries[3]], series[queries[4]]
	t.exposureAvailable = len(entrypoints)+len(paths)+len(lbs) > 0

	routeLevel := map[objKey]string{} // (cluster, namespace, kind/ingressroute)
	for _, e := range entrypoints {
		k := objKey{e[cl], e["namespace"], e["ingressroute"]}
		routeLevel[k] = model.WiderExposure(routeLevel[k], t.entrypointExposure(e["entrypoint"]))
	}
	svcLevel := map[objKey]string{} // (cluster, namespace, service)
	for _, r := range routes {
		if kind := r["service_kind"]; kind != "" && kind != "Service" {
			continue // TraefikService and the like
		}
		lvl, ok := routeLevel[objKey{r[cl], r["namespace"], r["ingressroute"]}]
		if !ok {
			continue
		}
		ns := r["service_namespace"]
		if ns == "" {
			ns = r["namespace"]
		}
		k := objKey{r[cl], ns, r["service"]}
		svcLevel[k] = model.WiderExposure(svcLevel[k], lvl)
	}
	ingressLevel := map[objKey]string{} // (cluster, namespace, ingress)
	for _, i := range ingresses {
		ingressLevel[objKey{i[cl], i["namespace"], i["ingress"]}] = t.ingressClassExposure(i["ingressclass"])
	}
	for _, p := range paths {
		if p["service_name"] == "" {
			continue // resource backend
		}
		lvl, ok := ingressLevel[objKey{p[cl], p["namespace"], p["ingress"]}]
		if !ok {
			lvl = t.ingressClassExposure("")
		}
		k := objKey{p[cl], p["namespace"], p["service_name"]}
		svcLevel[k] = model.WiderExposure(svcLevel[k], lvl)
	}
	for _, lb := range lbs {
		// Internal load balancers get a private IP, or a hostname with
		// "internal" on AWS ("internal-…").
		lvl := model.ExposureInternet
		if ip, err := netip.ParseAddr(lb["ip"]); strings.Contains(lb["hostname"], "internal") || err == nil && ip.IsPrivate() {
			lvl = model.ExposureInternal
		}
		k := objKey{lb[cl], lb["namespace"], lb["service"]}
		svcLevel[k] = model.WiderExposure(svcLevel[k], lvl)
	}
	podByIP := map[[2]string]objKey{}
	for _, p := range pods {
		if p["pod_ip"] == "" || p["host_network"] == "true" { // host network pods share the node IP
			continue
		}
		podByIP[[2]string{p[cl], p["pod_ip"]}] = objKey{p[cl], p["namespace"], p["pod"]}
	}
	out := map[objKey]string{}
	for _, e := range endpoints {
		lvl, ok := svcLevel[objKey{e[cl], e["namespace"], e["endpoint"]}]
		if !ok {
			continue
		}
		if pod, ok := podByIP[[2]string{e[cl], e["ip"]}]; ok {
			out[pod] = model.WiderExposure(out[pod], lvl)
		}
	}
	return out, nil
}

// ingressClassExposure classifies an Ingress class.
func (t *Prometheus) ingressClassExposure(class string) string {
	if lvl, ok := t.IngressClasses[class]; ok {
		return lvl
	}
	if strings.Contains(class, "internal") || strings.Contains(class, "private") {
		return model.ExposureInternal
	}
	return model.ExposureInternet
}

func (t *Prometheus) envLabel() string {
	if t.EnvLabel == "" {
		return "env"
	}
	return t.EnvLabel
}

func (t *Prometheus) clusterLabel() string {
	if t.ClusterLabel == "" {
		return "cluster"
	}
	return t.ClusterLabel
}

func (t *Prometheus) query(ctx context.Context, q string) ([]map[string]string, error) {
	// partial_response=false (Thanos): if a store is down we skip this sync
	// instead of believing a whole cluster stopped running. Prometheus ignores it.
	u := strings.TrimRight(t.URL, "/") + "/api/v1/query?" + url.Values{
		"query":            {q},
		"dedup":            {"true"},
		"partial_response": {"false"},
	}.Encode()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode (HTTP %d): %w", resp.StatusCode, err)
	}
	if body.Status != "success" {
		return nil, fmt.Errorf("prometheus: %s", body.Error)
	}
	out := make([]map[string]string, len(body.Data.Result))
	for i, r := range body.Data.Result {
		m := r.Metric
		if m[t.envLabel()] == "" && t.DefaultEnv != "" {
			m[t.envLabel()] = t.DefaultEnv
		}
		if m[t.clusterLabel()] == "" {
			m[t.clusterLabel()] = cmpOr(t.DefaultCluster, "default")
		}
		out[i] = m
	}
	return out, nil
}

// entrypointExposure classifies a Traefik entrypoint.
func (t *Prometheus) entrypointExposure(ep string) string {
	public := t.PublicEntrypoints
	if len(public) == 0 {
		public = []string{"web", "websecure"}
	}
	switch {
	case slices.Contains(public, ep):
		return model.ExposureInternet
	case strings.HasSuffix(ep, "-internal") || strings.HasSuffix(ep, "-int"):
		return model.ExposureInternal
	}
	if t.unknown == nil {
		t.unknown = map[string]bool{}
	}
	if !t.unknown[ep] && t.Log != nil {
		t.unknown[ep] = true
		t.Log.Warn("unclassified Traefik entrypoint, treated as internet-facing: set PAINDASH_PUBLIC_ENTRYPOINTS", "entrypoint", ep)
	}
	return model.ExposureInternet
}

type objKey struct{ cluster, namespace, name string }

type owner struct{ kind, name string }

func ownerMap(series []map[string]string, clusterLabel, nameLabel string) map[objKey]owner {
	m := map[objKey]owner{}
	for _, s := range series {
		kind := s["owner_kind"]
		if kind == "" || kind == "<none>" {
			continue
		}
		k := objKey{s[clusterLabel], s["namespace"], s[nameLabel]}
		// Prefer the controller owner when an object has several.
		if _, seen := m[k]; seen && s["owner_is_controller"] != "true" {
			continue
		}
		m[k] = owner{kind, s["owner_name"]}
	}
	return m
}

// Controller-made names, to find the owner of a ReplicaSet or Job that is not
// exported: deleted before its pods, or not scraped yet when they start.
var (
	// <deployment>-<pod-template-hash>, in the "safe" alphabet of
	// k8s.io/apimachinery's rand.SafeEncodeString.
	rsNameRe = regexp.MustCompile(`^(.+)-[bcdfghjklmnpqrstvwxz2456789]{6,10}$`)
	// <cronjob>-<scheduled time in minutes>.
	jobNameRe = regexp.MustCompile(`^(.+)-[0-9]{8,}$`)
)

// exported lists the objects that have a series, owned or not.
func exported(series []map[string]string, clusterLabel, nameLabel string) map[objKey]bool {
	m := map[objKey]bool{}
	for _, s := range series {
		m[objKey{s[clusterLabel], s["namespace"], s[nameLabel]}] = true
	}
	return m
}

// resolve turns kube-state-metrics series into containers attributed to their
// top-level workload: Pod -> ReplicaSet -> Deployment, Pod -> Job -> CronJob.
func resolve(containers, podOwners, rsOwners, jobOwners []map[string]string, envLabel, clusterLabel string) []resolved {
	pods := ownerMap(podOwners, clusterLabel, "pod")
	rss := ownerMap(rsOwners, clusterLabel, "replicaset")
	jobs := ownerMap(jobOwners, clusterLabel, "job_name")
	rsSeen := exported(rsOwners, clusterLabel, "replicaset")
	jobSeen := exported(jobOwners, clusterLabel, "job_name")

	seen := map[string]int{}
	var out []resolved
	for _, s := range containers {
		digest, ref := parseImageID(s["image_id"], s["image_spec"])
		if digest == "" {
			continue // container not started yet, or runtime without digest
		}
		c := model.Container{
			Env:       s[envLabel],
			Container: s["container"],
			Image:     s["image_spec"],
			Ref:       ref,
			Digest:    digest,
		}
		c.Cluster, c.Namespace = s[clusterLabel], s["namespace"]
		c.Kind, c.Name = "Pod", s["pod"]
		pk := objKey{c.Cluster, c.Namespace, s["pod"]}
		if c.Image == "" {
			c.Image = ref
		}
		if o, ok := pods[objKey{c.Cluster, c.Namespace, c.Name}]; ok {
			c.Kind, c.Name = o.kind, o.name
			switch o.kind {
			case "ReplicaSet":
				k := objKey{c.Cluster, c.Namespace, o.name}
				if p, ok := rss[k]; ok {
					c.Kind, c.Name = p.kind, p.name
				} else if m := rsNameRe.FindStringSubmatch(o.name); m != nil && !rsSeen[k] {
					c.Kind, c.Name = "Deployment", m[1]
				}
			case "Job":
				k := objKey{c.Cluster, c.Namespace, o.name}
				if p, ok := jobs[k]; ok {
					c.Kind, c.Name = p.kind, p.name
				} else if m := jobNameRe.FindStringSubmatch(o.name); m != nil && !jobSeen[k] {
					c.Kind, c.Name = "CronJob", m[1]
				}
			}
		}
		if i, ok := seen[c.Key()]; ok {
			out[i].pods = append(out[i].pods, pk)
		} else {
			seen[c.Key()] = len(out)
			out = append(out, resolved{Container: c, pods: []objKey{pk}})
		}
	}
	return out
}

// resolved is a container with the pods running it, to attach exposure.
type resolved struct {
	model.Container
	pods []objKey
}

func stripPodKeys(rs []resolved) []model.Container {
	out := make([]model.Container, len(rs))
	for i, r := range rs {
		out[i] = r.Container
	}
	return out
}

// parseImageID extracts the manifest digest and a pullable reference from
// kube-state-metrics' image_id ("repo@sha256:...", possibly prefixed with
// docker-pullable://). A bare "sha256:..." is an image config ID on some
// runtimes, not a manifest digest, so we only trust it via image_spec.
func parseImageID(imageID, imageSpec string) (digest, ref string) {
	id := strings.TrimPrefix(imageID, "docker-pullable://")
	if i := strings.LastIndex(id, "@sha256:"); i > 0 {
		return id[i+1:], id
	}
	if i := strings.LastIndex(imageSpec, "@sha256:"); i > 0 {
		return imageSpec[i+1:], imageSpec
	}
	return "", ""
}

// Tag returns a short human label for an image reference: its tag, or a
// shortened digest.
func Tag(image string) string {
	if i := strings.LastIndex(image, "@sha256:"); i >= 0 {
		d := image[i+len("@sha256:"):]
		if len(d) > 12 {
			d = d[:12]
		}
		repo := image[:i]
		if t := tagOf(repo); t != "" {
			return t
		}
		return "sha256:" + d
	}
	if t := tagOf(image); t != "" {
		return t
	}
	return image
}

func tagOf(ref string) string {
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		return ref[colon+1:]
	}
	return ""
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
