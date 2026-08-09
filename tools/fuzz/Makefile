# tools/fuzz — host fuzzing for the kernel's remote-facing parsers.
#
# Needs clang with libFuzzer (the kernel's own cross toolchain is NOT used —
# these build for the host so ASan/UBSan and libFuzzer are available).
#
#   make && python3 seeds_eth.py . && ./fuzz_netrx corpus_ethrx
#
# See README.md for what these do and do not cover.

AEGIS := $(abspath $(CURDIR)/../..)
KNET  := $(AEGIS)/kernel/net

# Plain `=`, not `?=`: make predefines CC=cc, which `?=` would not override.
# A command-line CC=... still wins.
CC     = clang
SAN    := -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
CFLAGS := -g -O1 -fno-omit-frame-pointer -Wall $(SAN)

# The shim MUST come first so its arch.h/printk.h/lockrank.h win over the real
# ones; everything else is the genuine kernel source.
INC := -Ishim -I$(KNET) -I$(AEGIS)/kernel/core -I$(AEGIS)/kernel/fs \
       -I$(AEGIS)/kernel/sched -I$(AEGIS)/kernel/proc -I$(AEGIS)/kernel/mm \
       -I$(AEGIS)/kernel/signal -I$(AEGIS)/kernel/cap \
       -I$(AEGIS)/kernel/arch/x86_64 -I$(AEGIS)/kernel

STRING := $(AEGIS)/kernel/lib/string.c

all: fuzz_netrx fuzz_ethrx

# Full stack: Ethernet -> ARP / IPv4 -> ICMP / TCP / UDP, with a listening
# TCP port and a bound UDP port so the state machines are live.
fuzz_netrx: fuzz_netrx.c $(KNET)/eth.c $(KNET)/ip.c $(KNET)/tcp.c $(KNET)/udp.c $(STRING)
	$(CC) $(CFLAGS) $(INC) -o $@ $^

# Narrower: Ethernet/ARP/IPv4/ICMP only, L4 stubbed. Faster, and isolates a
# finding to the lower layers.
fuzz_ethrx: fuzz_ethrx.c $(KNET)/eth.c $(KNET)/ip.c $(STRING)
	$(CC) $(CFLAGS) -Ishim -I$(KNET) -I$(AEGIS)/kernel/core -o $@ $^

seeds:
	python3 seeds_eth.py .

clean:
	rm -f fuzz_netrx fuzz_ethrx crash-* leak-* timeout-* oom-*
	rm -rf corpus_ethrx

.PHONY: all seeds clean
