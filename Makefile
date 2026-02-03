# We cannot use $(shell pwd), which will return unix path format on Windows,
# making it hard to use.
cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

TOP := $(cur_dir)
# RUSTFLAGS that are likely to be tweaked by developers. For example,
# while we enable debug logs by default here, some might want to strip them
# for minimal code size / consumed cycles.
CUSTOM_RUSTFLAGS := -C debug-assertions
# Additional cargo args to append here. For example, one can use
# make test CARGO_ARGS="-- --nocapture" so as to inspect data emitted to
# stdout in unit tests
CARGO_ARGS :=
MODE := release
# Tweak this to change the clang version to use for building C code. By default
# we use a bash script with some heuristics to find clang in current system.
CLANG := $(shell $(TOP)/scripts/find_clang)
# When this is set, a single contract will be built instead of all contracts
CONTRACT :=
# By default, we would clean build/{release,debug} folder first, in case old
# contracts are mixed together with new ones, if for some reason you want to
# revert this behavior, you can change this to anything other than true
CLEAN_BUILD_DIR_FIRST := true
BUILD_DIR := build/$(MODE)

# C compiler toolchain for RISC-V CKB target
C_TARGET := riscv64-unknown-elf
CC := $(C_TARGET)-gcc
LD := $(C_TARGET)-gcc
OBJCOPY := $(C_TARGET)-objcopy
C_CFLAGS := -O3 -I deps/molecule -I deps/secp256k1/src -I deps/secp256k1 -I c -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function -g
C_LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections

# secp256k1 source dependency
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h

# Docker image for C script builds (official CKB RISC-V toolchain)
C_BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

# C_BUILD_METHOD: native or docker (default: docker)
C_BUILD_METHOD ?= docker

ifeq (release,$(MODE))
	MODE_ARGS := --release
endif

# Pass setups to child make processes
export CUSTOM_RUSTFLAGS
export TOP
export CARGO_ARGS
export MODE
export CLANG
export BUILD_DIR

default: build test

# Unified build target: builds both C and Rust scripts
build: build-c build-rust-no-clean

# Build Rust contracts only
build-rust:
	@if [ "x$(CLEAN_BUILD_DIR_FIRST)" = "xtrue" ]; then \
		echo "Cleaning $(BUILD_DIR) directory..."; \
		rm -rf $(BUILD_DIR); \
	fi
	$(MAKE) build-rust-no-clean

# Build Rust without cleaning
build-rust-no-clean:
	mkdir -p $(BUILD_DIR)
	@set -eu; \
	if [ "x$(CONTRACT)" = "x" ]; then \
		for contract in $(wildcard contracts/*); do \
			$(MAKE) -e -C $$contract build; \
		done; \
		for crate in $(wildcard crates/*); do \
			cargo build -p $$(basename $$crate) $(MODE_ARGS) $(CARGO_ARGS); \
		done; \
		for sim in $(wildcard native-simulators/*); do \
			cargo build -p $$(basename $$sim) $(CARGO_ARGS); \
		done; \
	else \
		$(MAKE) -e -C contracts/$(CONTRACT) build; \
		cargo build -p $(CONTRACT)-sim; \
	fi;

# Run a single make task for a specific contract. For example:
#
# make run CONTRACT=stack-reorder TASK=adjust_stack_size STACK_SIZE=0x200000
TASK :=
run:
	$(MAKE) -e -C contracts/$(CONTRACT) $(TASK)

# test, check, clippy and fmt here are provided for completeness,
# there is nothing wrong invoking cargo directly instead of make.
test:
	cargo test $(CARGO_ARGS)

check:
	cargo check $(CARGO_ARGS)

clippy:
	cargo clippy $(CARGO_ARGS)

fmt:
	cargo fmt $(CARGO_ARGS)

# Arbitrary cargo command is supported here. For example:
#
# make cargo CARGO_CMD=expand CARGO_ARGS="--ugly"
#
# Invokes:
# cargo expand --ugly
CARGO_CMD :=
cargo:
	cargo $(CARGO_CMD) $(CARGO_ARGS)

# ============================================
# C Script Build Targets
# ============================================

# Build C scripts (use C_BUILD_METHOD=native or C_BUILD_METHOD=docker, default: docker)
build-c:
	@if [ "$(C_BUILD_METHOD)" = "native" ]; then \
		$(MAKE) build-c-native; \
	else \
		$(MAKE) build-c-docker; \
	fi

# Build all C scripts natively (requires RISC-V toolchain with newlib)
build-c-native: $(BUILD_DIR)/secp256k1_blake160_sighash_all $(BUILD_DIR)/secp256k1_blake160_multisig_all $(BUILD_DIR)/secp256k1_data

# Build C scripts via Docker
build-c-docker:
	docker run --rm -v `pwd`:/code $(C_BUILDER_DOCKER) bash -c "cd /code && make build-c-native"

$(BUILD_DIR)/secp256k1_blake160_sighash_all: c/secp256k1_blake160_sighash_all.c c/protocol.h c/common.h c/utils.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	mkdir -p $(BUILD_DIR)
	$(CC) $(C_CFLAGS) $(C_LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

$(BUILD_DIR)/secp256k1_blake160_multisig_all: c/secp256k1_blake160_multisig_all.c c/protocol.h c/common.h c/utils.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	mkdir -p $(BUILD_DIR)
	$(CC) $(C_CFLAGS) $(C_LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

# Copy secp256k1_data to build directory (required by C scripts at runtime)
$(BUILD_DIR)/secp256k1_data: specs/cells/secp256k1_data
	mkdir -p $(BUILD_DIR)
	cp $< $@

# secp256k1 data info header generation
build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc $(C_CFLAGS) -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(C_TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

clean:
	rm -rf build
	cargo clean
	-cd deps/secp256k1 && [ -f "Makefile" ] && make clean

TEMPLATE_TYPE := --git
TEMPLATE_REPO := https://github.com/cryptape/ckb-script-templates
CRATE :=
TEMPLATE := contract
DESTINATION := contracts
generate:
	@set -eu; \
	if [ "x$(CRATE)" = "x" ]; then \
		mkdir -p $(DESTINATION); \
		cargo generate $(TEMPLATE_TYPE) $(TEMPLATE_REPO) $(TEMPLATE) \
			--destination $(DESTINATION); \
		GENERATED_DIR=$$(ls -dt $(DESTINATION)/* | head -n 1); \
		if [ -f "$$GENERATED_DIR/.cargo-generate/tests.rs" ]; then \
			cat $$GENERATED_DIR/.cargo-generate/tests.rs >> tests/src/tests.rs; \
			rm -rf $$GENERATED_DIR/.cargo-generate/; \
		fi; \
		sed "s,@@INSERTION_POINT@@,@@INSERTION_POINT@@\n  \"$$GENERATED_DIR\"\,," Cargo.toml > Cargo.toml.new; \
		mv Cargo.toml.new Cargo.toml; \
	else \
		mkdir -p $(DESTINATION); \
		cargo generate $(TEMPLATE_TYPE) $(TEMPLATE_REPO) $(TEMPLATE) \
			--destination $(DESTINATION) \
			--name $(CRATE); \
		if [ -f "$(DESTINATION)/$(CRATE)/.cargo-generate/tests.rs" ]; then \
			cat $(DESTINATION)/$(CRATE)/.cargo-generate/tests.rs >> tests/src/tests.rs; \
			rm -rf $(DESTINATION)/$(CRATE)/.cargo-generate/; \
		fi; \
		sed '/@@INSERTION_POINT@@/s/$$/\n  "$(DESTINATION)\/$(CRATE)",/' Cargo.toml > Cargo.toml.new; \
		mv Cargo.toml.new Cargo.toml; \
	fi;

generate-native-simulator:
	@set -eu; \
	if [ -z "$(CRATE)" ]; then \
		echo "Error: Must have CRATE=<Contract Name>"; \
		exit 1; \
	fi; \
	mkdir -p native-simulators; \
	cargo generate $(TEMPLATE_TYPE) $(TEMPLATE_REPO) native-simulator \
		-n $(CRATE)-sim \
		--destination native-simulators; \
	sed '/@@INSERTION_POINT@@/s/$$/\n  "native-simulators\/$(CRATE)-sim",/' Cargo.toml > Cargo.toml.new; \
	mv Cargo.toml.new Cargo.toml; \
	if [ ! -f "contracts/$(CRATE)/Cargo.toml" ]; then \
		echo "Warning: This is a non-existent contract and needs to be processed manually"; \
		echo "		Otherwise compilation may fail."; \
	fi;

prepare:
	rustup target add riscv64imac-unknown-none-elf

# Generate checksum info for reproducible build
CHECKSUM_FILE := build/checksums-$(MODE).txt
checksum: build
	shasum -a 256 build/$(MODE)/* > $(CHECKSUM_FILE)

.PHONY: build build-rust build-rust-no-clean build-c build-c-native build-c-docker test check clippy fmt cargo clean prepare checksum
