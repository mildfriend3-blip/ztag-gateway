# Distributed Zero-Trust Access Gateway
# ---------------------------------------------------------------------------
# Everything is reproducible from this file: build, unit tests, policy tests,
# the local topology and the load/attack measurements used in the report.

SHELL      := /bin/bash
GO         ?= go
VERSION    ?= 0.1.0
IMAGE      ?= ghcr.io/example/ztag-gateway:$(VERSION)
OPA        ?= opa
BIN        := bin

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## Verify the module graph (the gateway has no third-party deps)
	$(GO) mod tidy

.PHONY: fmt
fmt: ## Format all Go sources
	$(GO) fmt ./...

.PHONY: vet
vet: ## Static analysis
	$(GO) vet ./...

.PHONY: build
build: ## Build every binary into ./bin
	@mkdir -p $(BIN)
	$(GO) build -trimpath -o $(BIN)/ztag-proxy     ./cmd/proxy
	$(GO) build -trimpath -o $(BIN)/ztag-logworker ./cmd/logworker
	$(GO) build -trimpath -o $(BIN)/ztag-tokengen  ./cmd/tokengen
	$(GO) build -trimpath -o $(BIN)/ztag-loadgen   ./cmd/loadgen
	$(GO) build -trimpath -o $(BIN)/ztag-echo      ./cmd/echo

.PHONY: test
test: ## Run Go unit tests
	$(GO) test ./... -count=1

.PHONY: race
race: ## Run unit tests with the race detector
	$(GO) test -race ./... -count=1

.PHONY: bench
bench: ## Micro-benchmarks (token verification, hot path)
	$(GO) test -run=^$$ -bench=. -benchmem ./internal/...

.PHONY: policy-test
policy-test: ## Run the OPA policy unit tests
	$(OPA) test policies -v

.PHONY: policy-fmt
policy-fmt: ## Check Rego formatting
	$(OPA) fmt --fail policies

.PHONY: check
check: fmt vet test policy-test ## Everything CI runs

.PHONY: env
env: ## Generate .env with random local secrets (gitignored, never committed)
	@if [ -f .env ]; then \
	  echo ".env already exists, leaving it alone"; \
	else \
	  printf 'ZTAG_JWT_SECRET=%s\nZTAG_ADMIN_TOKEN=%s\n' \
	    "$$(openssl rand -hex 32)" "$$(openssl rand -hex 24)" > .env; \
	  chmod 600 .env; \
	  echo "wrote .env with freshly generated secrets"; \
	fi

.PHONY: up
up: env ## Start the local topology (redis, opa, gateway, services, logworker)
	docker compose up --build -d
	@echo "gateway on http://localhost:8443"

.PHONY: down
down: ## Stop the local topology
	docker compose down -v

.PHONY: logs
logs: ## Tail gateway and logworker logs
	docker compose logs -f gateway logworker

.PHONY: token
token: ## Print a demo token
	docker compose run --rm tools

.PHONY: smoke
smoke: ## Run the end-to-end checks against a running gateway
	bash scripts/smoke.sh

.PHONY: attack
attack: ## Replay the three attack shapes against a running gateway
	bash scripts/attack-demo.sh

.PHONY: image
image: ## Build the container image
	docker build -t $(IMAGE) .

.PHONY: k8s-apply
k8s-apply: ## Apply the Kubernetes manifests
	kubectl apply -k deploy/k8s

.PHONY: k8s-delete
k8s-delete: ## Remove the Kubernetes resources
	kubectl delete -k deploy/k8s

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf $(BIN)
