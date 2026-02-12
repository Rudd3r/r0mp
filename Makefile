.PHONY: build build-init clean clean-all test test-long lint
.PHONY: setup-dev download-assets verify verify-qemu

GO := go
GOFLAGS := 
LDFLAGS := -s -w
JOBS ?= $(shell nproc)
BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

BIN_DIR := bin
BUILD_DIR := build
INIT_BIN := $(BIN_DIR)/raftinit
R0MP_BIN := $(BIN_DIR)/r0mp

# Asset download configuration
ASSETS_URL := https://github.com/Rudd3r/assets/releases/download/1.0/release.tar.gz
ASSETS_ARCHIVE := $(BUILD_DIR)/release.tar.gz
GOARCH ?= $(shell $(GO) env GOARCH)
ASSETS_SRC_DIR := $(BUILD_DIR)/$(GOARCH)

build: r0mp

r0mp: asset-init
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) $(GOFLAGS) -o $(R0MP_BIN) ./cmd/r0mp/

download-assets: $(ASSETS_ARCHIVE)
	@if [ ! -d "$(BUILD_DIR)/amd64" ] || [ ! -d "$(BUILD_DIR)/arm64" ]; then \
		echo "Extracting assets..."; \
		mkdir -p $(BUILD_DIR); \
		tar -xzf $(ASSETS_ARCHIVE) -C $(BUILD_DIR); \
		echo "Assets extracted to $(BUILD_DIR)"; \
	else \
		echo "Assets already extracted, skipping extraction"; \
	fi

$(ASSETS_ARCHIVE):
	@echo "Downloading assets from $(ASSETS_URL)"
	@mkdir -p $(BUILD_DIR)
	@curl -L -o $(ASSETS_ARCHIVE) $(ASSETS_URL)

asset-init: build-init download-assets
	@mkdir -p pkg/assets
	@cp -v $(INIT_BIN) pkg/assets/
	@cp -v $(ASSETS_SRC_DIR)/e2fsck pkg/assets/
	@cp -v $(ASSETS_SRC_DIR)/mke2fs pkg/assets/
	@cp -v $(ASSETS_SRC_DIR)/initrd.gz pkg/assets/
	@cp -v $(ASSETS_SRC_DIR)/vmlinuz pkg/assets/

clean:
	@rm -rfv $(BIN_DIR)
	@rm -fv pkg/assets/e2fsck \
        pkg/assets/raftinit \
        pkg/assets/mke2fs \
        pkg/assets/initrd.gz \
        pkg/assets/vmlinuz

clean-all: clean
	@rm -rfv $(BUILD_DIR)

test: asset-init lint
	$(GO) test -short -v -skip TestQEMUIntegration ./...

test-long: asset-init lint
	$(GO) test -v ./...

test-qemu: asset-init
	$(GO) test -v -run TestQEMUIntegration -short ./pkg/raftinit/

test-qemu-debug: asset-init
	DEBUG=1 $(GO) test -v -run TestQEMUIntegration -short ./pkg/raftinit/

test-qemu-long: asset-init
	$(GO) test -v -run TestQEMUIntegration ./pkg/raftinit/

test-qemu-long-debug: asset-init
	DEBUG=1 $(GO) test -v -run TestQEMUIntegration

verify: clean setup-dev build test

verify-qemu: verify test-qemu

lint:
	@golangci-lint run

build-init:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) $(GOFLAGS) -o $(INIT_BIN) ./pkg/internal/cmd/raftinit/

setup-dev: download-assets
	./scripts/setup-dev-dependencies.sh
