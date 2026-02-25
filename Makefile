# https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: down ## Setup the development environment
	docker compose up --build -d

.PHONY: up
up: ## Start the development environment
	docker compose up -d

.PHONY: down
down: ## Stop the development environment
	docker compose down -t 0

.PHONY: test
test: tidy vendor ## Run tests
	docker compose exec promptinel_app go test ./... --cover --short --race --shuffle=on --parallel=3

.PHONY: coverage
coverage: ## Generate test coverage report
	docker compose exec promptinel_app go test ./... -coverprofile=coverage.out
	docker compose exec promptinel_app go tool cover -html=coverage.out -o coverage.html

.PHONY: lint
lint: tidy vendor ## Run linters
	if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		docker compose exec promptinel_app golangci-lint run; \
	fi

.PHONY: vuln
vuln: tidy vendor ## Run dependency vulnerability scan
	if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		docker compose exec promptinel_app govulncheck ./...; \
	fi

.PHONY: fmt
fmt: ## Format the code
	docker compose exec promptinel_app go fmt ./...

.PHONY: vet
vet: ## Vet the code
	docker compose exec promptinel_app go vet ./...

.PHONY: fix
fix: ## Apply go fixes
	docker compose exec promptinel_app go fix ./...

.PHONY: tidy
tidy: ## Tidy the go modules
	docker compose exec promptinel_app go mod tidy

.PHONY: vendor
vendor: ## Vendor the go modules
	docker compose exec promptinel_app go mod vendor

.PHONY: logs
logs: ## Follow the application logs
	docker compose logs -f promptinel_app

.PHONY: build
build: tidy vendor ## Build the application inside the container
	if [ -z "$(BUILD_VERSION)" ]; then \
		echo "Error: BUILD_VERSION is not set. Please run 'export BUILD_VERSION=x.x.x && make build'"; \
		exit 1; \
	fi
	docker compose exec promptinel_app go build -buildvcs=false -ldflags="-X 'github.com/CunningFatalist/promptinel/cmd.Version=$(BUILD_VERSION)'" -o build/promptinel main.go

.PHONY: clean
clean: ## Clean up generated files
	rm -f coverage.out coverage.html
	rm -rf vendor build

.PHONY: shell
shell: ## Open a shell in the application container
	docker compose exec -it promptinel_app bash

.PHONY: test-docker
test-docker: ## Test the docker setup
	.docker/tests/run.sh
