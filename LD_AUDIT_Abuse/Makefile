# LD_AUDIT Interface Abuse POC - Makefile
#
# Usage:
#   make              - Build all components
#   make demo         - Run all demonstrations
#   make explore      - Run the audit explorer
#   make attack       - Run the evil audit library
#   make hijack       - Run the symbol hijacker
#   make clean        - Remove built files

CC = gcc
CFLAGS = -Wall -Wextra -g

# Targets
VICTIM = victim
AUDIT_EXPLORER = libaudit_explorer.so
EVIL_AUDIT = libevil_audit.so
AUDIT_HIJACK = libaudit_hijack.so

.PHONY: all clean demo explore attack hijack compare

all: $(VICTIM) $(AUDIT_EXPLORER) $(EVIL_AUDIT) $(AUDIT_HIJACK)

# ═══════════════════════════════════════════════════════════════════════════
# BUILD TARGETS
# ═══════════════════════════════════════════════════════════════════════════

$(VICTIM): victim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@"

$(AUDIT_EXPLORER): audit_explorer.c
	$(CC) -shared -fPIC -o $@ $< -ldl
	@echo "[+] Built: $@ (audit interface explorer)"

$(EVIL_AUDIT): evil_audit.c
	$(CC) -shared -fPIC -o $@ $< -ldl
	@echo "[+] Built: $@ (malicious audit library)"

$(AUDIT_HIJACK): audit_hijack.c
	$(CC) -shared -fPIC -o $@ $< -ldl
	@echo "[+] Built: $@ (symbol hijacking library)"

# ═══════════════════════════════════════════════════════════════════════════
# DEMONSTRATION TARGETS
# ═══════════════════════════════════════════════════════════════════════════

demo: all normal explore attack hijack
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  ALL DEMONSTRATIONS COMPLETE"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Attack log:"
	@cat /tmp/ld_audit_attack.log 2>/dev/null | tail -20 || echo "(no log)"
	@echo ""
	@echo "Hijack log:"
	@cat /tmp/ld_audit_hijack.log 2>/dev/null || echo "(no log)"

# Normal execution (no LD_AUDIT)
normal: $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 1: NORMAL EXECUTION (no LD_AUDIT)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="db_pass_123" ./$(VICTIM)

# Explore the LD_AUDIT interface
explore: $(VICTIM) $(AUDIT_EXPLORER)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 2: LD_AUDIT INTERFACE EXPLORATION"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Running: LD_AUDIT=./$(AUDIT_EXPLORER) ./$(VICTIM)"
	@echo ""
	LD_AUDIT=./$(AUDIT_EXPLORER) SECRET_API_KEY="sk-secret-12345" ./$(VICTIM)

# Run the evil audit library
attack: $(VICTIM) $(EVIL_AUDIT)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 3: MALICIOUS LD_AUDIT ATTACK"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Running: LD_AUDIT=./$(EVIL_AUDIT) ./$(VICTIM)"
	@echo ""
	LD_AUDIT=./$(EVIL_AUDIT) SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="super_secret" AUTH_TOKEN="ghp_token123" ./$(VICTIM)

# Run the symbol hijacker
hijack: $(VICTIM) $(AUDIT_HIJACK)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 4: SYMBOL HIJACKING VIA LD_AUDIT"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Running: LD_AUDIT=./$(AUDIT_HIJACK) ./$(VICTIM)"
	@echo ""
	@echo "Notice how getenv() and puts() are redirected to our hooks!"
	@echo ""
	LD_AUDIT=./$(AUDIT_HIJACK) SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="hijacked_pass" ./$(VICTIM)

# Compare LD_AUDIT vs LD_PRELOAD
compare: $(VICTIM) $(EVIL_AUDIT)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  LD_AUDIT vs LD_PRELOAD COMPARISON"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "LD_AUDIT advantages over LD_PRELOAD:"
	@echo "  1. Runs BEFORE LD_PRELOAD libraries"
	@echo "  2. Can intercept library search paths"
	@echo "  3. Sees all symbol bindings"
	@echo "  4. Can redirect ANY symbol (not just exported ones)"
	@echo "  5. Gets pre-init callback before any constructors"
	@echo ""
	@echo "LD_AUDIT disadvantages:"
	@echo "  1. More complex to implement"
	@echo "  2. Ignored for setuid binaries (like LD_PRELOAD)"
	@echo "  3. Can't intercept statically linked functions"
	@echo ""

# Show what LD_AUDIT can see
show-callbacks:
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  LD_AUDIT CALLBACK FUNCTIONS"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "  la_version(version)"
	@echo "    Called first - negotiate API version"
	@echo ""
	@echo "  la_objsearch(name, cookie, flag)"
	@echo "    Called when searching for a library"
	@echo "    Can REDIRECT library paths!"
	@echo ""
	@echo "  la_activity(cookie, flag)"
	@echo "    Called when linking state changes"
	@echo ""
	@echo "  la_objopen(map, lmid, cookie)"
	@echo "    Called when a library is loaded"
	@echo ""
	@echo "  la_preinit(cookie)"
	@echo "    Called BEFORE any .init functions"
	@echo "    Earlier than LD_PRELOAD constructors!"
	@echo ""
	@echo "  la_symbind64(sym, ndx, refcook, defcook, flags, symname)"
	@echo "    Called for EACH symbol binding"
	@echo "    Can REDIRECT any symbol!"
	@echo ""
	@echo "  la_pltenter() / la_pltexit()"
	@echo "    Called on PLT entry/exit (function call tracing)"
	@echo ""

clean:
	rm -f $(VICTIM) $(AUDIT_EXPLORER) $(EVIL_AUDIT) $(AUDIT_HIJACK)
	rm -f /tmp/ld_audit_attack.log /tmp/ld_audit_hijack.log
	@echo "[+] Cleaned"
