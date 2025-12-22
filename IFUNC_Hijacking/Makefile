# IFUNC Hijacking POC - Makefile
#
# Usage:
#   make              - Build all components
#   make demo         - Run all demonstrations
#   make explore      - Run the IFUNC explorer
#   make hijack       - Run IFUNC hijacking demo
#   make attack       - Run resolver attack demo
#   make clean        - Remove built files

CC = gcc
CFLAGS = -Wall -Wextra -g

# Targets
EXPLORER = ifunc_explorer
VICTIM = victim
EVIL_IFUNC = libevil_ifunc.so
RESOLVER_ATTACK = libresolver_attack.so

.PHONY: all clean demo explore hijack attack normal show-glibc-ifunc

all: $(EXPLORER) $(VICTIM) $(EVIL_IFUNC) $(RESOLVER_ATTACK)

# ═══════════════════════════════════════════════════════════════════════════
# BUILD TARGETS
# ═══════════════════════════════════════════════════════════════════════════

$(EXPLORER): ifunc_explorer.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@ (IFUNC mechanism explorer)"

$(VICTIM): victim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@"

$(EVIL_IFUNC): evil_ifunc.c
	$(CC) -shared -fPIC -o $@ $< -ldl
	@echo "[+] Built: $@ (IFUNC hijacking library)"

$(RESOLVER_ATTACK): resolver_attack.c
	$(CC) -shared -fPIC -o $@ $< -ldl
	@echo "[+] Built: $@ (resolver attack library)"

# ═══════════════════════════════════════════════════════════════════════════
# DEMONSTRATION TARGETS
# ═══════════════════════════════════════════════════════════════════════════

demo: all explore normal hijack attack
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  ALL DEMONSTRATIONS COMPLETE"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "IFUNC Hijack Log:"
	@cat /tmp/ifunc_hijack.log 2>/dev/null | tail -10 || echo "(no log)"
	@echo ""
	@echo "Resolver Attack Log:"
	@cat /tmp/resolver_attack.log 2>/dev/null | tail -15 || echo "(no log)"

# Explore IFUNC mechanism
explore: $(EXPLORER)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  EXPLORING IFUNC MECHANISM"
	@echo "════════════════════════════════════════════════════════════════"
	./$(EXPLORER)

# Normal execution
normal: $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 1: NORMAL EXECUTION (no IFUNC hijacking)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="db_pass" ./$(VICTIM)

# IFUNC hijacking demonstration
hijack: $(VICTIM) $(EVIL_IFUNC)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 2: IFUNC HIJACKING ATTACK"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Running: LD_PRELOAD=./$(EVIL_IFUNC) ./$(VICTIM)"
	@echo ""
	@echo "Notice: Resolvers run BEFORE the victim's constructor!"
	@echo ""
	LD_PRELOAD=./$(EVIL_IFUNC) SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="super_secret" AUTH_TOKEN="ghp_token" ./$(VICTIM)

# Resolver-based attack
attack: $(VICTIM) $(RESOLVER_ATTACK)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 3: RESOLVER ATTACK (Earliest Execution)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Running: LD_PRELOAD=./$(RESOLVER_ATTACK) ./$(VICTIM)"
	@echo ""
	@echo "This demonstrates the EARLIEST possible code execution!"
	@echo ""
	LD_PRELOAD=./$(RESOLVER_ATTACK) SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="resolver_attack" AUTH_TOKEN="early_token" ./$(VICTIM)

# Show IFUNC symbols in glibc
show-glibc-ifunc:
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  IFUNC SYMBOLS IN GLIBC"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep IFUNC | head -20"
	@echo ""
	@objdump -T /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | grep IFUNC | head -20 || \
		echo "(objdump not available)"
	@echo ""
	@echo "Common IFUNC functions in glibc:"
	@echo "  memcpy, memset, memmove, strcmp, strlen, strcpy..."
	@echo ""

# Show execution order comparison
show-order:
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  EXECUTION ORDER COMPARISON"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "  Execution order (earliest to latest):"
	@echo ""
	@echo "  1. IFUNC RESOLVERS        ← Runs during symbol resolution"
	@echo "     ↓"
	@echo "  2. LD_AUDIT la_preinit    ← Runs before constructors"
	@echo "     ↓"
	@echo "  3. LD_PRELOAD constructors"
	@echo "     ↓"
	@echo "  4. Library .init_array"
	@echo "     ↓"
	@echo "  5. Program .init_array"
	@echo "     ↓"
	@echo "  6. main()"
	@echo ""
	@echo "  IFUNC resolvers are THE EARLIEST user-space code execution!"
	@echo ""

clean:
	rm -f $(EXPLORER) $(VICTIM) $(EVIL_IFUNC) $(RESOLVER_ATTACK)
	rm -f /tmp/ifunc_hijack.log /tmp/resolver_attack.log
	@echo "[+] Cleaned"
