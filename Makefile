# command names
GO:=go
GOBINDIR:=$(shell go env GOPATH)/bin/
GOTEST="$(GOBINDIR)/gotestsum"
GOWINRES="$(GOBINDIR)/go-winres"
GOLIC="$(GOBINDIR)/go-licenses"

# build artifacts, sources
BUILD-DIR:=cmd
AGENT-WIN:=$(BUILD-DIR)/main_windows.go
AGENT-OTHER:=$(BUILD-DIR)/main_other.go
DEPS:=$(wildcard pkg/firmware/*/*.go) $(wildcard pkg/*/*.go)
DEPS-WIN:=$(AGENT-WIN) $(DEPS)
DEPS-OTHER:=$(AGENT-OTHER) $(DEPS)

# build-time parameters, values
RELEASE_ID?=$(shell git describe --tags)
GO_ENV:=CGO_ENABLED=0 GOARCH=amd64
LDFLAGS:=-X github.com/immune-gmbh/agent/v3/pkg/core.releaseId=$(RELEASE_ID) -s -w $(LDFLAGS_EXTRA)
LDFLAGS-STATIC:=$(LDFLAGS) -extldflags "-static"

# suppress lots of legacy SCCS and RCS lookups
MAKEFLAGS += --no-builtin-rules 

.DEFAULT_GOAL:=all
.PHONY: all
all: guard-all

# OS-specific make targets are used by Github unit test runners to avoid redundant builds
# As we don't (yet) have a macOS workflow run we'll cross-compile mac artifacts with Linux
Linux: deps guard-linux guard-osx
Windows: deps guard-win.exe
macOS: deps guard-osx

.PHONY: deps
deps:
	@echo "Fetching and installing dependencies.."
	@$(GO) mod download
	@$(GO) install github.com/tc-hib/go-winres@latest
	@$(GO) install gotest.tools/gotestsum@latest
	@$(GO) install github.com/google/go-licenses

# need to cd into the directory b/c the command doesn't accept output parameter
$(BUILD-DIR)/rsrc_windows_amd64.syso: deps winres/winres.json winres/icon.png winres/icon16.png winres/icon32.png winres/icon48.png
	cd cmd/; $(GOWINRES) make --in ../winres/winres.json --arch amd64 --product-version $(RELEASE_ID) --file-version $(RELEASE_ID)

guard-linux: $(DEPS-OTHER)
	$(GO_ENV) GOOS=linux   $(GO) build -C $(BUILD-DIR) -ldflags '$(LDFLAGS-STATIC)' -o $(PWD)/$@

guard-osx: $(DEPS-OTHER)
	$(GO_ENV) GOOS=darwin  $(GO) build -C $(BUILD-DIR) -ldflags '$(LDFLAGS-STATIC)' -o $(PWD)/$@

# need to build inside the proper directory or otherwise go build won't recognize the .syso file
guard-win.exe: $(BUILD-DIR)/rsrc_windows_amd64.syso $(DEPS-WIN)
	$(GO_ENV) GOOS=windows $(GO) build -C $(BUILD-DIR) -ldflags '$(LDFLAGS-STATIC)' -o $(PWD)/$@ 

.PHONY: guard-all
guard-all: Linux Windows macOS
	
.PHONY: clean
clean:
	rm -f guard-linux guard-osx guard-win.exe

.PHONY: test
test: deps
	$(GOTEST) -- -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: license-check
license-check: deps
	$(GOLIC) --logtostderr check --ignore github.com/immune-gmbh/agent --ignore command-line-arguments --exclude-restricted $(AGENT-OTHER)
	GOOS=windows $(GOLIC) --logtostderr check --ignore github.com/immune-gmbh/agent --ignore command-line-arguments --exclude-restricted $(AGENT-WIN)

# disable many builtin rules
.SUFFIXES:
