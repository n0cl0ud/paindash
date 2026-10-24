package inventory

import "testing"

func TestResolveOwners(t *testing.T) {
	const cl = "prod-1"
	containers := []map[string]string{
		{"env": "prod", "cluster": cl, "namespace": "orders", "pod": "api-7d9f-abcde", "container": "api",
			"image_spec": "ghcr.io/acme/api:v1.2.0", "image_id": "ghcr.io/acme/api@sha256:aaa"},
		// Second replica, same digest: deduplicated.
		{"env": "prod", "cluster": cl, "namespace": "orders", "pod": "api-7d9f-fghij", "container": "api",
			"image_spec": "ghcr.io/acme/api:v1.2.0", "image_id": "docker-pullable://ghcr.io/acme/api@sha256:aaa"},
		{"env": "prod", "cluster": cl, "namespace": "orders", "pod": "report-28800-xyz", "container": "report",
			"image_spec": "ghcr.io/acme/report@sha256:bbb", "image_id": "sha256:configid"},
		{"env": "prod", "cluster": cl, "namespace": "orders", "pod": "pending-pod", "container": "c",
			"image_spec": "busybox:1", "image_id": ""},
		{"env": "prod", "cluster": cl, "namespace": "kube-system", "pod": "standalone", "container": "c",
			"image_spec": "busybox:1", "image_id": "docker.io/library/busybox@sha256:ccc"},
	}
	podOwners := []map[string]string{
		{"cluster": cl, "namespace": "orders", "pod": "api-7d9f-abcde", "owner_kind": "ReplicaSet", "owner_name": "api-7d9f", "owner_is_controller": "true"},
		{"cluster": cl, "namespace": "orders", "pod": "api-7d9f-fghij", "owner_kind": "ReplicaSet", "owner_name": "api-7d9f", "owner_is_controller": "true"},
		{"cluster": cl, "namespace": "orders", "pod": "report-28800-xyz", "owner_kind": "Job", "owner_name": "report-28800", "owner_is_controller": "true"},
		{"cluster": cl, "namespace": "kube-system", "pod": "standalone", "owner_kind": "<none>", "owner_name": "<none>"},
	}
	rsOwners := []map[string]string{
		{"cluster": cl, "namespace": "orders", "replicaset": "api-7d9f", "owner_kind": "Deployment", "owner_name": "api", "owner_is_controller": "true"},
	}
	jobOwners := []map[string]string{
		{"cluster": cl, "namespace": "orders", "job_name": "report-28800", "owner_kind": "CronJob", "owner_name": "report", "owner_is_controller": "true"},
	}

	got := resolve(containers, podOwners, rsOwners, jobOwners, "env", "cluster")
	if len(got) != 3 {
		t.Fatalf("got %d containers: %+v", len(got), got)
	}
	want := []struct{ kind, name, digest, ref string }{
		{"Deployment", "api", "sha256:aaa", "ghcr.io/acme/api@sha256:aaa"},
		{"CronJob", "report", "sha256:bbb", "ghcr.io/acme/report@sha256:bbb"},
		{"Pod", "standalone", "sha256:ccc", "docker.io/library/busybox@sha256:ccc"},
	}
	for i, w := range want {
		c := got[i]
		if c.Kind != w.kind || c.Name != w.name || c.Digest != w.digest || c.Ref != w.ref || c.Env != "prod" || c.Cluster != cl {
			t.Errorf("#%d = %+v, want %+v", i, c, w)
		}
	}
}

// A ReplicaSet or Job deleted before its pods (or not scraped yet) has no
// owner series: its controller-made name still tells the workload.
func TestResolveMissingOwners(t *testing.T) {
	const cl = "ops-1"
	ctr := func(pod, digest string) map[string]string {
		return map[string]string{"env": "ops", "cluster": cl, "namespace": "default", "pod": pod, "container": "c",
			"image_spec": "nginx:1.27", "image_id": "docker.io/library/nginx@" + digest}
	}
	owned := func(pod, kind, name string) map[string]string {
		return map[string]string{"cluster": cl, "namespace": "default", "pod": pod, "owner_kind": kind, "owner_name": name, "owner_is_controller": "true"}
	}
	containers := []map[string]string{
		ctr("web-5c8d7b9f4d-x7k2p", "sha256:a"),
		ctr("cache-6b7c9-abcde", "sha256:b"),
		ctr("report-29312345-q9z8w", "sha256:c"),
		ctr("manual-rs-4f8kd", "sha256:d"),
	}
	podOwners := []map[string]string{
		owned("web-5c8d7b9f4d-x7k2p", "ReplicaSet", "web-5c8d7b9f4d"), // RS already deleted
		owned("cache-6b7c9-abcde", "ReplicaSet", "cache-6b7c9"),       // not a pod-template-hash: kept
		owned("report-29312345-q9z8w", "Job", "report-29312345"),      // Job already deleted
		owned("manual-rs-4f8kd", "ReplicaSet", "manual-rs"),
	}
	// A standalone ReplicaSet is exported without owner: it stays one.
	rsOwners := []map[string]string{
		{"cluster": cl, "namespace": "default", "replicaset": "manual-rs", "owner_kind": "<none>", "owner_name": "<none>"},
	}
	got := resolve(containers, podOwners, rsOwners, nil, "env", "cluster")
	want := []string{"Deployment/web", "ReplicaSet/cache-6b7c9", "CronJob/report", "ReplicaSet/manual-rs"}
	if len(got) != len(want) {
		t.Fatalf("got %d containers: %+v", len(got), got)
	}
	for i, w := range want {
		if g := got[i].Kind + "/" + got[i].Name; g != w {
			t.Errorf("#%d = %s, want %s", i, g, w)
		}
	}
}

func TestTag(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/acme/api:v1.2.0":                     "v1.2.0",
		"localhost:5000/api":                          "localhost:5000/api",
		"ghcr.io/acme/api:v1@sha256:0123456789abcdef": "v1",
		"ghcr.io/acme/api@sha256:0123456789abcdef":    "sha256:0123456789ab",
	} {
		if got := Tag(in); got != want {
			t.Errorf("Tag(%q) = %q, want %q", in, got, want)
		}
	}
}
