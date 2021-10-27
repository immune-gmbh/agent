# command names
GO:=go
GOTEST:=$(GO) test -v

# build artifacts, sources
SRCS-CLIENT:=cmd/main.go 
DEPS-CLIENT:=$(SRCS-CLIENT) pkg/**/*.go

# build-time parameters, values
RELEASE_ID?=$(shell git describe --tags)
GO_ENV:=CGO_ENABLED=0 GOARCH=amd64
CGO_ENV:=CGO_ENABLED=1 GOARCH=amd64
LDFLAGS:=-X main.releaseId=$(RELEASE_ID) -w $(LDFLAGS_EXTRA)
LDFLAGS-STATIC:=$(LDFLAGS) -extldflags "-static"

# suppress lots of legacy SCCS and RCS lookups
MAKEFLAGS += --no-builtin-rules 

.DEFAULT_GOAL:=all
.PHONY: all
all: guard-all

# OS-specific make targets are used by Github unit test runners to avoid redundant builds
# As we don't (yet) have a macOS workflow run we'll cross-compile mac artifacts with Linux
Linux: deps guard-linux guard-osx guard-linux-sim
Windows: deps guard-win.exe
macOS: deps guard-osx

.PHONY: deps
deps:
	@echo "Fetching and installing dependencies.."
	@$(GO) mod download
	@$(GO) install github.com/tc-hib/go-winres@latest
	@$(GO) install github.com/immune-gmbh/go-licenses

# need to cd into the directory b/c the command doesn't accept output parameter
cmd/rsrc_windows_amd64.syso: deps winres/winres.json winres/icon.png winres/icon16.png winres/icon32.png winres/icon48.png
	cd cmd/; go-winres make --in ../winres/winres.json --arch amd64 --product-version $(RELEASE_ID) --file-version $(RELEASE_ID)

guard-linux: $(DEPS-CLIENT)
	$(GO_ENV) GOOS=linux   $(GO) build -ldflags '$(LDFLAGS-STATIC)' -o $@ $(SRCS-CLIENT)

guard-linux-sim: $(DEPS-CLIENT)
	$(CGO_ENV) GOOS=linux   $(GO) build -ldflags '$(LDFLAGS)' -o $@ $(SRCS-CLIENT)

guard-osx: $(DEPS-CLIENT)
	$(GO_ENV) GOOS=darwin  $(GO) build -ldflags '$(LDFLAGS-STATIC)' -o $@ $(SRCS-CLIENT)

# need to build inside the proper directory or otherwise go build won't recognize the .syso file
guard-win.exe: cmd/rsrc_windows_amd64.syso $(DEPS-CLIENT)
	cd cmd/; $(GO_ENV) GOOS=windows $(GO) build -ldflags '$(LDFLAGS-STATIC)' -o ../$@

.PHONY: guard-all
guard-all: Linux Windows macOS
	
.PHONY: clean
clean:
	rm -f guard-linux guard-osx guard-win.exe guard-linux-sim

.PHONY: test
test:
	$(GOTEST) -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: license-check
license-check: deps
	go-licenses --logtostderr check --exclude-restricted cmd/

# disable many builtin rules
.SUFFIXES:
