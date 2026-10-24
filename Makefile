.PHONY: web build test demo snapshot

DB_URL ?= postgres://paindash:paindash@127.0.0.1:55432/paindash

web:
	cd web && npm ci && npm run build

build: web
	go build -o bin/paindash ./cmd/paindash

test:
	go vet ./... && go test ./...

# Simulated clusters + scanner, no auth: http://localhost:8080
demo: build
	docker compose up -d --wait
	PAINDASH_DATABASE_URL=$(DB_URL) PAINDASH_DEMO=1 PAINDASH_AUTH=disabled \
	PAINDASH_LISTEN=127.0.0.1:8080 PAINDASH_INTERNAL_LISTEN=127.0.0.1:9091 ./bin/paindash

# Print the inventory paindash sees through Prometheus, read-only, to check the
# labels before installing: make snapshot PROMETHEUS_URL=http://localhost:9090
# (add PAINDASH_DEFAULT_ENV=prod for a single Prometheus without env label).
snapshot:
	PAINDASH_PROMETHEUS_URL=$(PROMETHEUS_URL) go run ./cmd/paindash snapshot

