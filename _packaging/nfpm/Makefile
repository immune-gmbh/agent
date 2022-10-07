# command names
GO:=go
NFPM:=nfpm

# build-time parameters, values
RELEASE_ID?=$(shell git describe --tags)
export RELEASE_ID := $(RELEASE_ID)
NFPMFLAGS=package -f nfpm-packages.yml

# build artifacts
SRCS:=guard-linux
TARGETS:=guard_1-$(RELEASE_ID).1_amd64.deb guard-1-$(RELEASE_ID)-1.x86_64.rpm

.PHONY: deps
deps:
	@echo "Fetching and installing dependencies.."
	@$(GO) install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.19.2

# suppress lots of legacy SCCS and RCS lookups
MAKEFLAGS += --no-builtin-rules

.DEFAULT_GOAL:=all
.PHONY: all
all: $(TARGETS)

%.deb: $(SRCS) deps
	$(NFPM) $(NFPMFLAGS) -p deb -t $@

%.rpm: $(SRCS) deps
	$(NFPM) $(NFPMFLAGS) -p rpm -t $@

.PHONY: clean
clean:
	rm -f guard_*.deb guard-*.rpm

# disable many builtin rules
.SUFFIXES:
