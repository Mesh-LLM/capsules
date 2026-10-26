# SPDX-License-Identifier: Apache-2.0
# Build, package and install the capsules plugin from this checkout.
# The package is always for this machine (the host triple); release packages
# for other platforms come from the release workflow.
# See INSTALL.md "Build it yourself". `make` lists the targets.

VERSION   := $(shell sed -n 's/^version *= *"\([^"]*\)".*/\1/p' plugin.toml)
override TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
MESH_LLM  ?= mesh-llm
BINARY    := crates/evidence-plugin/target/release/capsules
ARCHIVE   := dist/capsules-$(VERSION)-$(TARGET).tar.gz

.DEFAULT_GOAL := help
.PHONY: help web-ui plugin package install clean check-tar

help: ## List the targets
	@echo "Targets (VERSION=$(VERSION) TARGET=$(TARGET)):"
	@sed -n 's/^\([a-z-]*\):.*## \(.*\)/  make \1\t\2/p' $(MAKEFILE_LIST)
	@echo "Install into a locally built node: make install MESH_LLM=/path/to/mesh-llm"

web-ui: ## Build the Evidence page into bundle/
	cd web-ui && pnpm install --frozen-lockfile && pnpm build

plugin: ## Build the plugin executable (release)
	cargo build --release --locked --manifest-path crates/evidence-plugin/Cargo.toml

check-tar:
	@command -v gtar >/dev/null 2>&1 || tar --version 2>/dev/null | grep -q 'GNU tar' || \
	  { echo "make: GNU tar is required (macOS: brew install gnu-tar)" >&2; exit 1; }

package: check-tar ## Build both and write dist/capsules-<version>-<target>.tar.gz
	$(MAKE) web-ui plugin
	scripts/package.sh $(VERSION) $(TARGET) $(BINARY) dist

install: package ## Install the package with mesh-llm (override with MESH_LLM=)
	"$(MESH_LLM)" plugins install --archive "$(ARCHIVE)" --name capsules --version $(VERSION)

clean: ## Remove dist/, bundle/ and the plugin's cargo target
	rm -rf dist bundle
	cargo clean --manifest-path crates/evidence-plugin/Cargo.toml
