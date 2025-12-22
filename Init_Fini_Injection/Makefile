# Init/Fini Array Injection POC - Makefile
#
# Usage:
#   make              - Build all components
#   make demo         - Run all demonstrations
#   make order        - Show execution order
#   make hijack       - Demonstrate array hijacking
#   make inject       - Inject constructor via LD_PRELOAD
#   make explore      - Explore init/fini arrays
#   make clean        - Remove built files

CC = gcc
CFLAGS = -Wall -Wextra -g

# Targets
EXPLORER = initfini_explorer
ORDER = execution_order
HIJACK = initarray_hijack
EVIL_SO = evil_constructor.so
VICTIM = victim

.PHONY: all clean demo order hijack inject explore

all: $(EXPLORER) $(ORDER) $(HIJACK) $(EVIL_SO) $(VICTIM)

# ═══════════════════════════════════════════════════════════════════════════
# BUILD TARGETS
# ═══════════════════════════════════════════════════════════════════════════

$(EXPLORER): initfini_explorer.c
	$(CC) $(CFLAGS) -o $@ $< -ldl
	@echo "[+] Built: $@ (init/fini array explorer)"

$(ORDER): execution_order.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@ (execution order demo)"

# Need -no-pie and -z norelro for writable fini_array
$(HIJACK): initarray_hijack.c
	$(CC) $(CFLAGS) -no-pie -Wl,-z,norelro -o $@ $<
	@echo "[+] Built: $@ (array hijacking demo, no RELRO)"

$(EVIL_SO): evil_constructor.c
	$(CC) -shared -fPIC -o $@ $<
	@echo "[+] Built: $@ (malicious constructor library)"

$(VICTIM): victim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@"

# ═══════════════════════════════════════════════════════════════════════════
# DEMONSTRATION TARGETS
# ═══════════════════════════════════════════════════════════════════════════

demo: all order hijack inject explore
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  ALL DEMONSTRATIONS COMPLETE"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Log file:"
	@cat /tmp/init_injection_log.txt 2>/dev/null || echo "(no log)"

# Show constructor/destructor execution order
order: $(ORDER)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  EXECUTION ORDER DEMONSTRATION"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	./$(ORDER)

# Demonstrate fini_array hijacking
hijack: $(HIJACK)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  FINI_ARRAY HIJACKING DEMONSTRATION"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	./$(HIJACK)

# Inject constructor via LD_PRELOAD
inject: $(EVIL_SO) $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 1: VICTIM RUNNING NORMALLY"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	./$(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 2: VICTIM WITH INJECTED CONSTRUCTOR (LD_PRELOAD)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	LD_PRELOAD=./$(EVIL_SO) ./$(VICTIM)

# Explore init/fini arrays
explore: $(EXPLORER)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  EXPLORING INIT/FINI ARRAYS"
	@echo "════════════════════════════════════════════════════════════════"
	./$(EXPLORER)

# Show sections with objdump
show-sections: $(HIJACK)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  INIT/FINI SECTIONS (via objdump)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> .init_array section:"
	@objdump -s -j .init_array $(HIJACK) 2>/dev/null || echo "(not found)"
	@echo ""
	@echo ">>> .fini_array section:"
	@objdump -s -j .fini_array $(HIJACK) 2>/dev/null || echo "(not found)"
	@echo ""
	@echo ">>> Dynamic entries:"
	@readelf -d $(HIJACK) | grep -E "INIT|FINI"

# Show sections with readelf
show-dynamic: $(EXPLORER)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  DYNAMIC SECTION INIT/FINI ENTRIES"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	readelf -d $(EXPLORER) | grep -E "INIT|FINI|PREINIT"

clean:
	rm -f $(EXPLORER) $(ORDER) $(HIJACK) $(EVIL_SO) $(VICTIM)
	rm -f /tmp/init_injection_log.txt
	@echo "[+] Cleaned"
