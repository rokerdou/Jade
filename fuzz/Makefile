# Fuzz harness for the Trezor protocol parsing stack.
# Compiles the business sources unmodified (same file list as the
# eth_tron_address_gate host test) together with a libFuzzer driver.
# The gate test file is linked in with its main() renamed, purely to reuse
# its wally/jade host shims - no business source is altered.

CC ?= clang

ROOT := ..
MAIN := $(ROOT)/main

CFLAGS := -std=c11 -g -O1 \
	-fsanitize=address,undefined \
	-fno-sanitize-recover=undefined \
	-fsanitize-coverage=trace-pc-guard \
	-fno-omit-frame-pointer \
	-DTREZOR_ETHEREUM_DEFINITIONS_HOST_TEST \
	-Wno-everything \
	-I$(MAIN) \
	-I$(MAIN)/test/host_shims \
	-I$(ROOT)/components/esp32_bc-ur/src \
	-I$(ROOT)/components/libwally-core \
	-I$(ROOT)/components/libwally-core/upstream/src \
	-I$(ROOT)/components/libwally-core/upstream/src/ccan \
	-I$(ROOT)/components/libwally-core/upstream/include

BUSINESS_SRCS := \
	$(MAIN)/chains/authorization.c \
	$(MAIN)/chains/confirm_summary.c \
	$(MAIN)/chains/evm_abi.c \
	$(MAIN)/crypto/keccak256.c \
	$(MAIN)/chains/bitcoin/address.c \
	$(MAIN)/chains/bitcoin/confirm.c \
	$(MAIN)/chains/bitcoin/path.c \
	$(MAIN)/chains/bitcoin/wallet.c \
	$(MAIN)/chains/ethereum/address.c \
	$(MAIN)/chains/ethereum/authorize.c \
	$(MAIN)/chains/ethereum/confirm.c \
	$(MAIN)/chains/ethereum/digest.c \
	$(MAIN)/chains/ethereum/path.c \
	$(MAIN)/chains/ethereum/safe_tx.c \
	$(MAIN)/chains/ethereum/sign.c \
	$(MAIN)/chains/ethereum/tx.c \
	$(MAIN)/chains/ethereum/tx_request.c \
	$(MAIN)/chains/ethereum/wallet.c \
	$(MAIN)/protocols/trezor/bitcoin/messages.c \
	$(MAIN)/protocols/trezor/bitcoin/multisig.c \
	$(MAIN)/protocols/trezor/bitcoin/multisig_tx.c \
	$(MAIN)/protocols/trezor/bitcoin/normalizer.c \
	$(MAIN)/protocols/trezor/bitcoin/script_builder.c \
	$(MAIN)/protocols/trezor/bitcoin/protocol.c \
	$(MAIN)/protocols/trezor/bitcoin/policy.c \
	$(MAIN)/protocols/trezor/bitcoin/public_node.c \
	$(MAIN)/protocols/trezor/bitcoin/requests.c \
	$(MAIN)/protocols/trezor/bitcoin/script_policy.c \
	$(MAIN)/protocols/trezor/bitcoin/signing_state.c \
	$(MAIN)/protocols/trezor/bitcoin/prev_tx_verifier.c \
	$(MAIN)/protocols/trezor/dispatcher.c \
	$(MAIN)/protocols/trezor/ethereum/protocol.c \
	$(MAIN)/protocols/trezor/ethereum/definitions.c \
	$(MAIN)/protocols/trezor/ethereum/normalizer.c \
	$(MAIN)/protocols/trezor/ethereum/safe_normalizer.c \
	$(MAIN)/protocols/trezor/failure.c \
	$(MAIN)/protocols/trezor/features.c \
	$(MAIN)/protocols/trezor/protobuf.c \
	$(MAIN)/protocols/trezor/public_key.c \
	$(MAIN)/protocols/trezor/session.c \
	$(MAIN)/protocols/trezor/trace.c \
	$(MAIN)/protocols/trezor/wire.c \
	$(ROOT)/components/esp32_bc-ur/src/sha2.c \
	$(ROOT)/components/esp32_bc-ur/src/memzero.c \
	$(ROOT)/components/libwally-core/upstream/src/ccan/ccan/crypto/ripemd160/ripemd160.c \
	$(MAIN)/chains/tron/address.c \
	$(MAIN)/chains/tron/authorize.c \
	$(MAIN)/chains/tron/confirm.c \
	$(MAIN)/chains/tron/path.c \
	$(MAIN)/chains/tron/tx.c \
	$(MAIN)/chains/tron/wallet.c

GATE_SHIM_SRC := $(MAIN)/test/eth_tron_address_gate.c

BIN := fuzz_jade

.PHONY: all clean run

all: $(BIN)

GATE_OBJ := gate_shim.o

$(GATE_OBJ): $(GATE_SHIM_SRC)
	$(CC) $(CFLAGS) -Dmain=gate_disabled_main -c $< -o $@

$(BIN): driver.c mini_fuzz.c $(BUSINESS_SRCS) $(GATE_OBJ)
	$(CC) $(CFLAGS) \
		driver.c mini_fuzz.c $(GATE_OBJ) $(BUSINESS_SRCS) \
		-o $(BIN)

# Selftest: same harness but with protobuf.c replaced by a copy carrying a
# deliberately planted stack OOB write. Run `make selftest` - it MUST crash
# within seconds and save an artifact, proving the detection pipeline works.
selftest: driver.c mini_fuzz.c $(filter-out ../main/protocols/trezor/protobuf.c,$(BUSINESS_SRCS)) $(GATE_OBJ) protobuf_selftest.c
	$(CC) $(CFLAGS) -I../main/protocols/trezor \
		driver.c mini_fuzz.c $(GATE_OBJ) protobuf_selftest.c \
		$(filter-out ../main/protocols/trezor/protobuf.c,$(BUSINESS_SRCS)) \
		-o fuzz_jade_selftest

run: $(BIN)
	mkdir -p artifacts
	./$(BIN) 120

clean:
	rm -f $(BIN)
	rm -rf corpus artifacts
