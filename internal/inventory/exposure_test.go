package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/n0cl0ud/paindash/internal/model"
)

// fakePrometheus answers each instant query with the series of its metric.
func fakePrometheus(t *testing.T, series map[string][]map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		metric := q[:strings.IndexAny(q+"{", "{")]
		res := []map[string]any{}
		for _, m := range series[metric] {
			res = append(res, map[string]any{"metric": m, "value": []any{0, "1"}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"result": res}})
	}))
}

// lbl builds the labels of a series of env prod, in cluster prod-1 unless kv
// sets another.
func lbl(kv ...string) map[string]string {
	m := map[string]string{"cluster": "prod-1", "env": "prod"}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func podContainer(ns, pod, name string) map[string]string {
	return lbl("namespace", ns, "pod", pod, "container", name, "image_spec", name+":1", "image_id", "r/"+name+"@sha256:"+name)
}

// sliceEndpoint is a kube_endpointslice_endpoints series of a pod.
func sliceEndpoint(ns, slice, pod, address string) map[string]string {
	return lbl("namespace", ns, "endpointslice", slice, "targetref_kind", "Pod", "targetref_name", pod,
		"targetref_namespace", ns, "address", address, "ready", "true")
}

// exposures takes a snapshot and returns the exposure of each workload, by
// namespace/name.
func exposures(t *testing.T, p *Prometheus) map[string]string {
	t.Helper()
	cs, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range cs {
		got[c.Namespace+"/"+c.Name] = c.Exposure
	}
	return got
}

func TestExposure(t *testing.T) {
	series := map[string][]map[string]string{
		"kube_pod_container_info": {
			podContainer("web", "front-1", "front"), podContainer("orders", "api-1", "api"),
			podContainer("ingress", "traefik-1", "traefik"), podContainer("ingress", "edge-1", "edge"),
			podContainer("batch", "job-1", "job"), podContainer("iot", "mqtt-1", "mqtt"),
			podContainer("ops", "probe-1", "probe"), podContainer("shop", "shop-1", "shop"),
			podContainer("admin", "admin-1", "admin"), podContainer("db", "pg-1", "pg"),
		},
		"kube_ingress_info": {
			lbl("namespace", "shop", "ingress", "shop", "ingressclass", "nginx"),
			lbl("namespace", "admin", "ingress", "admin", "ingressclass", "nginx-internal"),
		},
		"kube_ingress_path": {
			lbl("namespace", "shop", "ingress", "shop", "host", "shop.example.com", "path", "/", "service_name", "shop", "service_port", "80"),
			lbl("namespace", "admin", "ingress", "admin", "host", "admin.example.internal", "path", "/", "service_name", "admin", "service_port", "80"),
		},
		"kube_traefik_ingressroute_entrypoint": {
			lbl("namespace", "web", "ingressroute", "front", "entrypoint", "websecure"),
			lbl("namespace", "web", "ingressroute", "front-int", "entrypoint", "websecure-internal"),
			lbl("namespace", "auth", "ingressroute", "api", "entrypoint", "websecure-internal"),
			lbl("namespace", "ops", "ingressroute", "mystery", "entrypoint", "metrics"), // unknown: internet
		},
		"kube_traefik_ingressroutetcp_entrypoint": {
			// Same name as an HTTP route of another namespace, on a public TCP entrypoint.
			lbl("namespace", "iot", "ingressroute", "api", "entrypoint", "mqtt"),
		},
		"kube_traefik_ingressroutetcp_service": {
			lbl("namespace", "iot", "ingressroute", "api", "service", "mqtt"),
		},
		"kube_traefik_ingressroute_service": {
			lbl("namespace", "web", "ingressroute", "front", "service", "front"),
			lbl("namespace", "web", "ingressroute", "front-int", "service", "front"),
			lbl("namespace", "auth", "ingressroute", "api", "service", "api", "service_namespace", "orders"),
			lbl("namespace", "ops", "ingressroute", "mystery", "service", "probe"),
		},
		"kube_service_status_load_balancer_ingress": {
			lbl("namespace", "ingress", "service", "traefik", "hostname", "public-lb-abc.elb.amazonaws.com"),
			lbl("namespace", "ingress", "service", "traefik-internal", "hostname", "internal-lb-def.elb.amazonaws.com"),
			lbl("namespace", "db", "service", "pg", "ip", "10.20.0.5"), // private address: internal
		},
		"kube_pod_info": {
			lbl("namespace", "web", "pod", "front-1", "pod_ip", "10.0.0.1"),
			lbl("namespace", "orders", "pod", "api-1", "pod_ip", "10.0.0.2"),
			lbl("namespace", "ingress", "pod", "traefik-1", "pod_ip", "10.0.0.3"),
			// Two host network pods of the same node share its IP.
			lbl("namespace", "ingress", "pod", "edge-1", "pod_ip", "10.0.0.9", "host_network", "true"),
			lbl("namespace", "batch", "pod", "job-1", "pod_ip", "10.0.0.9", "host_network", "true"),
			lbl("namespace", "iot", "pod", "mqtt-1", "pod_ip", "10.0.0.4"),
			lbl("namespace", "ops", "pod", "probe-1", "pod_ip", "10.0.0.5"),
			lbl("namespace", "shop", "pod", "shop-1", "pod_ip", "10.0.0.6"),
			lbl("namespace", "admin", "pod", "admin-1", "pod_ip", "10.0.0.7"),
			lbl("namespace", "db", "pod", "pg-1", "pod_ip", "10.0.0.8"),
		},
	}
	endpoints := []map[string]string{
		lbl("namespace", "web", "endpoint", "front", "ip", "10.0.0.1"),
		lbl("namespace", "orders", "endpoint", "api", "ip", "10.0.0.2"),
		lbl("namespace", "ingress", "endpoint", "traefik", "ip", "10.0.0.3"),
		lbl("namespace", "ingress", "endpoint", "traefik-internal", "ip", "10.0.0.3"),
		lbl("namespace", "ingress", "endpoint", "traefik", "ip", "10.0.0.9"), // edge-1
		lbl("namespace", "iot", "endpoint", "mqtt", "ip", "10.0.0.4"),
		lbl("namespace", "ops", "endpoint", "probe", "ip", "10.0.0.5"),
		lbl("namespace", "shop", "endpoint", "shop", "ip", "10.0.0.6"),
		lbl("namespace", "admin", "endpoint", "admin", "ip", "10.0.0.7"),
		lbl("namespace", "db", "endpoint", "pg", "ip", "10.0.0.8"),
	}
	slices := []map[string]string{
		sliceEndpoint("web", "front-8z99r", "front-1", "10.0.0.1"),
		sliceEndpoint("orders", "api-5rdtt", "api-1", "10.0.0.2"),
		sliceEndpoint("ingress", "traefik-5g62k", "traefik-1", "10.0.0.3"),
		sliceEndpoint("ingress", "traefik-internal-sf42x", "traefik-1", "10.0.0.3"),
		sliceEndpoint("ingress", "traefik-5g62k", "edge-1", "10.0.0.9"),
		sliceEndpoint("iot", "mqtt-w6t7w", "mqtt-1", "10.0.0.4"),
		sliceEndpoint("ops", "probe-zbvvr", "probe-1", "10.0.0.5"),
		sliceEndpoint("shop", "shop-d8dll", "shop-1", "10.0.0.6"),
		sliceEndpoint("admin", "admin-jgwk5", "admin-1", "10.0.0.7"),
		sliceEndpoint("db", "pg-4x7kq", "pg-1", "10.0.0.8"),
	}
	want := map[string]string{
		"web/front-1":       model.ExposureInternet, // public wins over internal
		"orders/api-1":      model.ExposureInternal, // route in auth, Service in orders
		"ingress/traefik-1": model.ExposureInternet, // public LB wins over the internal one
		"batch/job-1":       model.ExposureNone,     // shares edge-1's IP
		"iot/mqtt-1":        model.ExposureInternet, // IngressRouteTCP on the public mqtt entrypoint
		"ops/probe-1":       model.ExposureInternet, // unknown entrypoint: never understated
		"shop/shop-1":       model.ExposureInternet, // Ingress, public class
		"admin/admin-1":     model.ExposureInternal, // Ingress, internal class
		"db/pg-1":           model.ExposureInternal, // LoadBalancer with a private IP
	}
	for _, tc := range []struct {
		name string
		join map[string][]map[string]string
		edge string // host network pod behind the public LB: only EndpointSlices name it
	}{
		{"endpoints", map[string][]map[string]string{"kube_endpoint_address": endpoints}, model.ExposureNone},
		{"endpointslices", map[string][]map[string]string{"kube_endpointslice_endpoints": slices}, model.ExposureInternet},
		{"both", map[string][]map[string]string{"kube_endpoint_address": endpoints, "kube_endpointslice_endpoints": slices}, model.ExposureInternet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := maps.Clone(series)
			maps.Copy(s, tc.join)
			srv := fakePrometheus(t, s)
			defer srv.Close()
			p := &Prometheus{URL: srv.URL, PublicEntrypoints: []string{"websecure", "mqtt"}}
			got := exposures(t, p)
			if !p.ExposureAvailable() {
				t.Error("exposure should be available")
			}
			w := maps.Clone(want)
			w["ingress/edge-1"] = tc.edge
			for k, w := range w {
				if got[k] != w {
					t.Errorf("%s: exposure %q, want %q", k, got[k], w)
				}
			}
		})
	}
}

// EndpointSlices are found by name: "<service>-" cut to 58 characters, then
// 5 random characters.
func TestEndpointSliceNames(t *testing.T) {
	const long = "long-service-name-for-endpointslice-truncation-check-abcdef" // 59 characters
	public := func(ns, svc string) map[string]string {
		return lbl("namespace", ns, "service", svc, "ip", "203.0.113.10")
	}
	oldKSM := sliceEndpoint("legacy", "old-k2p9d", "old-1", "10.0.1.1")
	oldKSM["namespace"] = "monitoring" // no namespace label before v2.11.0: kube-state-metrics' own
	node := sliceEndpoint("kube-system", "kubelet-bcdfg", "node-1", "10.0.2.1")
	node["targetref_kind"] = "Node"
	delete(node, "targetref_namespace")
	srv := fakePrometheus(t, map[string][]map[string]string{
		"kube_pod_container_info": {
			podContainer("app", "foo-1", "foo"), podContainer("app", "foo-bar-1", "foo-bar"),
			podContainer("app", "long-1", "long"), podContainer("app", "twin-1", "twin"),
			podContainer("app", "dual-1", "dual"), podContainer("legacy", "old-1", "old"),
			podContainer("kube-system", "node-1", "agent"), podContainer("app", "foo-admin-1", "foo-admin"),
		},
		"kube_service_status_load_balancer_ingress": {
			public("app", "foo"),
			lbl("namespace", "app", "service", "foo-bar", "ip", "10.20.0.5"),
			public("app", long), public("app", "dual"), public("legacy", "old"),
			public("kube-system", "kubelet"),
		},
		"kube_endpointslice_endpoints": {
			sliceEndpoint("app", "foo-bcdfg", "foo-1", "10.0.0.1"),
			sliceEndpoint("app", "foo-bar-hjklm", "foo-bar-1", "10.0.0.2"), // not foo's
			sliceEndpoint("app", long[:58]+"zbvvr", "long-1", "10.0.0.3"),
			sliceEndpoint("app", long[:58]+"q5x2n", "twin-1", "10.0.0.4"), // of a Service with the same first 58 characters, or long's
			sliceEndpoint("app", "dual-4kq2x", "dual-1", "10.0.0.5"),      // dual stack: one slice per family
			sliceEndpoint("app", "dual-7wz9b", "dual-1", "fd00::5"),
			oldKSM, node,
			sliceEndpoint("app", "foo-admin", "foo-admin-1", "10.0.0.6"), // named by hand after its own Service
		},
	})
	defer srv.Close()
	got := exposures(t, &Prometheus{URL: srv.URL})
	for k, w := range map[string]string{
		"app/foo-1":          model.ExposureInternet,
		"app/foo-bar-1":      model.ExposureInternal,
		"app/long-1":         model.ExposureInternet,
		"app/twin-1":         model.ExposureInternet, // ambiguous names are never understated
		"app/dual-1":         model.ExposureInternet,
		"legacy/old-1":       model.ExposureInternet,
		"kube-system/node-1": model.ExposureNone, // a Node, not a pod
		"app/foo-admin-1":    model.ExposureNone, // not foo's: "admin" is not a generated suffix
	} {
		if got[k] != w {
			t.Errorf("%s: exposure %q, want %q", k, got[k], w)
		}
	}
}

// Exposure is available only when every cluster with routes also has the
// series that lead from its Services to its pods.
func TestExposureAvailable(t *testing.T) {
	lb := func(cluster string) map[string]string {
		return lbl("cluster", cluster, "namespace", "web", "service", "front", "ip", "203.0.113.10")
	}
	slice := func(cluster string) map[string]string {
		s := sliceEndpoint("web", "front-8z99r", "front-1", "10.0.0.1")
		s["cluster"] = cluster
		return s
	}
	addr := func(cluster string) map[string]string {
		return lbl("cluster", cluster, "namespace", "web", "endpoint", "front", "ip", "10.0.0.1")
	}
	type series = map[string][]map[string]string
	for _, tc := range []struct {
		name   string
		series series
		want   bool
		warn   string // cluster reported without join series
	}{
		{"no routes", series{"kube_endpointslice_endpoints": {slice("prod-1")}}, false, ""},
		{"endpointslices", series{"kube_service_status_load_balancer_ingress": {lb("prod-1")}, "kube_endpointslice_endpoints": {slice("prod-1")}}, true, ""},
		{"endpoints", series{"kube_service_status_load_balancer_ingress": {lb("prod-1")}, "kube_endpoint_address": {addr("prod-1")}}, true, ""},
		{"one of each", series{
			"kube_service_status_load_balancer_ingress": {lb("prod-1"), lb("prod-2")},
			"kube_endpointslice_endpoints":              {slice("prod-1")},
			"kube_endpoint_address":                     {addr("prod-2")},
		}, true, ""},
		{"cluster without join series", series{
			"kube_service_status_load_balancer_ingress": {lb("prod-1"), lb("prod-2")},
			"kube_endpointslice_endpoints":              {slice("prod-1")},
		}, false, "prod-2"},
		{"cluster without routes", series{
			"kube_service_status_load_balancer_ingress": {lb("prod-1")},
			"kube_endpointslice_endpoints":              {slice("prod-1")},
			"kube_pod_container_info":                   {lbl("cluster", "prod-2", "namespace", "web", "pod", "front-1", "container", "front", "image_id", "r/front@sha256:aa")},
		}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakePrometheus(t, tc.series)
			defer srv.Close()
			var log bytes.Buffer
			p := &Prometheus{URL: srv.URL, Log: slog.New(slog.NewTextHandler(&log, nil))}
			for range 2 {
				if _, err := p.Snapshot(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if p.ExposureAvailable() != tc.want {
				t.Errorf("ExposureAvailable() = %v, want %v", p.ExposureAvailable(), tc.want)
			}
			warnings := strings.Count(log.String(), "exposure unavailable")
			if tc.warn == "" && warnings != 0 || tc.warn != "" && (warnings != 1 || !strings.Contains(log.String(), "cluster="+tc.warn)) {
				t.Errorf("log %q, want one warning for cluster %q", log.String(), tc.warn)
			}
		})
	}
}

// A single Prometheus has no env or cluster label: the defaults fill them in
// and no env filter applies.
func TestSingleCluster(t *testing.T) {
	srv := fakePrometheus(t, map[string][]map[string]string{
		"kube_pod_container_info": {{"namespace": "web", "pod": "front-1", "container": "front",
			"image_spec": "front:1", "image_id": "r/front@sha256:aa"}},
	})
	defer srv.Close()
	p := &Prometheus{URL: srv.URL, Envs: []string{"prod", "test"}, DefaultEnv: "prod"}
	cs, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Env != "prod" || cs[0].Cluster != "default" {
		t.Fatalf("got %+v", cs)
	}
}
