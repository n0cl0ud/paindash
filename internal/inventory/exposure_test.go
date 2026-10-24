package inventory

import (
	"context"
	"encoding/json"
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

func TestExposure(t *testing.T) {
	const cl = "prod-1"
	lbl := func(kv ...string) map[string]string {
		m := map[string]string{"cluster": cl, "env": "prod"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	container := func(ns, pod, name string) map[string]string {
		return lbl("namespace", ns, "pod", pod, "container", name, "image_spec", name+":1", "image_id", "r/"+name+"@sha256:"+name)
	}
	srv := fakePrometheus(t, map[string][]map[string]string{
		"kube_pod_container_info": {
			container("web", "front-1", "front"), container("orders", "api-1", "api"),
			container("ingress", "traefik-1", "traefik"), container("batch", "job-1", "job"),
			container("iot", "mqtt-1", "mqtt"), container("ops", "probe-1", "probe"),
			container("shop", "shop-1", "shop"), container("admin", "admin-1", "admin"), container("db", "pg-1", "pg"),
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
		"kube_endpoint_address": {
			lbl("namespace", "web", "endpoint", "front", "ip", "10.0.0.1"),
			lbl("namespace", "orders", "endpoint", "api", "ip", "10.0.0.2"),
			lbl("namespace", "ingress", "endpoint", "traefik", "ip", "10.0.0.3"),
			lbl("namespace", "ingress", "endpoint", "traefik-internal", "ip", "10.0.0.3"),
			lbl("namespace", "ingress", "endpoint", "traefik", "ip", "10.0.0.9"), // host network: ignored
			lbl("namespace", "iot", "endpoint", "mqtt", "ip", "10.0.0.4"),
			lbl("namespace", "ops", "endpoint", "probe", "ip", "10.0.0.5"),
			lbl("namespace", "shop", "endpoint", "shop", "ip", "10.0.0.6"),
			lbl("namespace", "admin", "endpoint", "admin", "ip", "10.0.0.7"),
			lbl("namespace", "db", "endpoint", "pg", "ip", "10.0.0.8"),
		},
		"kube_pod_info": {
			lbl("namespace", "web", "pod", "front-1", "pod_ip", "10.0.0.1"),
			lbl("namespace", "orders", "pod", "api-1", "pod_ip", "10.0.0.2"),
			lbl("namespace", "ingress", "pod", "traefik-1", "pod_ip", "10.0.0.3"),
			lbl("namespace", "batch", "pod", "job-1", "pod_ip", "10.0.0.9", "host_network", "true"),
			lbl("namespace", "iot", "pod", "mqtt-1", "pod_ip", "10.0.0.4"),
			lbl("namespace", "ops", "pod", "probe-1", "pod_ip", "10.0.0.5"),
			lbl("namespace", "shop", "pod", "shop-1", "pod_ip", "10.0.0.6"),
			lbl("namespace", "admin", "pod", "admin-1", "pod_ip", "10.0.0.7"),
			lbl("namespace", "db", "pod", "pg-1", "pod_ip", "10.0.0.8"),
		},
	})
	defer srv.Close()

	p := &Prometheus{URL: srv.URL, PublicEntrypoints: []string{"websecure", "mqtt"}}
	cs, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !p.ExposureAvailable() {
		t.Error("exposure should be available")
	}
	got := map[string]string{}
	for _, c := range cs {
		got[c.Namespace+"/"+c.Name] = c.Exposure
	}
	want := map[string]string{
		"web/front-1":       model.ExposureInternet, // public wins over internal
		"orders/api-1":      model.ExposureInternal, // route in auth, Service in orders
		"ingress/traefik-1": model.ExposureInternet, // public LB wins over the internal one
		"batch/job-1":       model.ExposureNone,
		"iot/mqtt-1":        model.ExposureInternet, // IngressRouteTCP on the public mqtt entrypoint
		"ops/probe-1":       model.ExposureInternet, // unknown entrypoint: never understated
		"shop/shop-1":       model.ExposureInternet, // Ingress, public class
		"admin/admin-1":     model.ExposureInternal, // Ingress, internal class
		"db/pg-1":           model.ExposureInternal, // LoadBalancer with a private IP
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: exposure %q, want %q", k, got[k], w)
		}
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
