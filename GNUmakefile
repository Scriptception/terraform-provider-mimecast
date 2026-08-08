GO ?= go
TERRAFORM ?= terraform

TFPLUGINDOCS_VERSION := v0.23.0
GOVULNCHECK_VERSION := v1.6.0
VERSION := $(shell tr -d '\r\n' < VERSION)

default: fmt-check test vet capability-check docs-check

build:
	$(GO) build -trimpath -v ./...

install: build
	$(GO) install -trimpath -v ./...

test:
	$(GO) test -race -cover -timeout=120s ./...
	cd tools && $(GO) test -race -cover -timeout=120s ./...

testacc-read:
	@tests="$$( $(GO) test ./internal/provider -run '^$$' -list '^TestAcc.*DataSource$$' )" || exit $$?; \
		printf '%s\n' "$$tests" | grep -Eq '^TestAcc.*DataSource$$' || { echo "No read-only acceptance tests match TestAcc.*DataSource" >&2; exit 1; }
	TF_ACC=1 $(GO) test -v -cover -timeout=30m ./internal/provider -run '^TestAcc.*DataSource$$'

testacc-mutation:
	@test "$$MIMECAST_ACC_MUTATION" = "1" || { echo "MIMECAST_ACC_MUTATION=1 is required" >&2; exit 1; }
	@test "$$MIMECAST_ACC_TENANT_DISPOSABLE" = "1" || { echo "MIMECAST_ACC_TENANT_DISPOSABLE=1 is required" >&2; exit 1; }
	@tests="$$( $(GO) test ./internal/provider -run '^$$' -list '^TestAcc.*Mutation$$' )" || exit $$?; \
		printf '%s\n' "$$tests" | grep -Eq '^TestAcc.*Mutation$$' || { echo "No mutation acceptance tests match TestAcc.*Mutation" >&2; exit 1; }
	TF_ACC=1 $(GO) test -v -cover -timeout=120m ./internal/provider -run '^TestAcc.*Mutation$$'

fmt:
	$(GO) fmt ./...
	cd tools && $(GO) fmt ./...
	$(TERRAFORM) fmt -recursive examples

fmt-check:
	@files="$$(gofmt -l $$(find . -name '*.go' -not -path './.terraform/*' -not -path './.local-tmp/*'))"; \
		test -z "$$files" || { echo "Go files require formatting:" >&2; echo "$$files" >&2; exit 1; }
	$(TERRAFORM) fmt -check -recursive examples

vet:
	$(GO) vet ./...
	cd tools && $(GO) vet ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	cd tools && $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

generate:
	cd tools && $(GO) run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@$(TFPLUGINDOCS_VERSION) generate --provider-name mimecast --provider-dir ..

capability-check:
	cd tools && $(GO) run ./capabilitycheck -manifest ../capabilities/api-v2.json -provider-root ..

capability-release-check:
	cd tools && $(GO) run ./capabilitycheck -offline -release -manifest ../capabilities/api-v2.json -provider-root .. -gap-doc ../docs/api-gaps.md

capability-doc:
	cd tools && $(GO) run ./capabilitycheck -offline -manifest ../capabilities/api-v2.json -provider-root .. -write-doc -doc ../docs/api-coverage.md -write-gap-doc -gap-doc ../docs/api-gaps.md

capability-refresh:
	cd tools && $(GO) run ./capabilitycheck -refresh -manifest ../capabilities/api-v2.json -provider-root .. -write-doc -doc ../docs/api-coverage.md -write-gap-doc -gap-doc ../docs/api-gaps.md

docs-check: generate capability-doc
	git diff --exit-code -- docs examples capabilities

version-check:
	@test -n "$(VERSION)" || { echo "VERSION is empty" >&2; exit 1; }
	@printf '%s\n' "$(VERSION)" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*)|([0-9]*[A-Za-z-][0-9A-Za-z-]*))(\.((0|[1-9][0-9]*)|([0-9]*[A-Za-z-][0-9A-Za-z-]*)))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$$' || { echo "VERSION must be a SemVer 2.0.0 version such as 0.2.0 or 0.2.0-rc.1" >&2; exit 1; }

release-check: version-check fmt-check test vet vuln capability-check capability-release-check docs-check build

clean:
	rm -f coverage.out
	rm -rf dist

.PHONY: default build install test testacc-read testacc-mutation fmt fmt-check vet vuln generate capability-check capability-release-check capability-doc capability-refresh docs-check version-check release-check clean
