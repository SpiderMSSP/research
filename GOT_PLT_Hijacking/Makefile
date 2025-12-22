# GOT/PLT Hijacking POC - Makefile
#
# Usage:
#   make              - Build all components
#   make demo         - Run the GOT hijacking demonstration
#   make inspect      - Run the GOT inspector on victim
#   make compare      - Compare RELRO protection levels
#   make clean        - Remove built files

CC = gcc
CFLAGS = -Wall -Wextra

# Targets
VICTIM_NO_RELRO = victim_no_relro
VICTIM_PARTIAL = victim_partial
VICTIM_FULL = victim_full
GOT_HIJACK = got_hijack_demo
GOT_INSPECTOR = got_inspector

.PHONY: all clean demo inspect compare show-got

all: $(VICTIM_NO_RELRO) $(VICTIM_PARTIAL) $(VICTIM_FULL) $(GOT_HIJACK) $(GOT_INSPECTOR)

# ═══════════════════════════════════════════════════════════════════════════
# VICTIM PROGRAMS - Different RELRO levels
# ═══════════════════════════════════════════════════════════════════════════

# NO RELRO - GOT is fully writable (most vulnerable)
$(VICTIM_NO_RELRO): victim.c
	$(CC) $(CFLAGS) -no-pie -Wl,-z,norelro -o $@ $<
	@echo "[+] Built: $@ (NO RELRO - GOT writable)"

# PARTIAL RELRO - .got read-only, .got.plt writable (default)
$(VICTIM_PARTIAL): victim.c
	$(CC) $(CFLAGS) -no-pie -Wl,-z,relro -o $@ $<
	@echo "[+] Built: $@ (PARTIAL RELRO)"

# FULL RELRO - Entire GOT is read-only (most secure)
$(VICTIM_FULL): victim.c
	$(CC) $(CFLAGS) -no-pie -Wl,-z,relro,-z,now -o $@ $<
	@echo "[+] Built: $@ (FULL RELRO - GOT read-only)"

# ═══════════════════════════════════════════════════════════════════════════
# GOT HIJACKING DEMO
# ═══════════════════════════════════════════════════════════════════════════

$(GOT_HIJACK): got_hijack_demo.c
	$(CC) $(CFLAGS) -no-pie -Wl,-z,norelro -o $@ $< -ldl
	@echo "[+] Built: $@ (with writable GOT for demo)"

# ═══════════════════════════════════════════════════════════════════════════
# GOT INSPECTOR TOOL
# ═══════════════════════════════════════════════════════════════════════════

$(GOT_INSPECTOR): got_inspector.c
	$(CC) $(CFLAGS) -o $@ $< -ldl
	@echo "[+] Built: $@"

# ═══════════════════════════════════════════════════════════════════════════
# DEMONSTRATION TARGETS
# ═══════════════════════════════════════════════════════════════════════════

# Run the main GOT hijacking demonstration
demo: $(GOT_HIJACK)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  RUNNING GOT/PLT HIJACKING DEMONSTRATION"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	./$(GOT_HIJACK)

# Inspect victim's GOT
inspect: $(GOT_INSPECTOR) $(VICTIM_NO_RELRO)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  INSPECTING GOT OF VICTIM BINARY"
	@echo "════════════════════════════════════════════════════════════════"
	./$(GOT_INSPECTOR) ./$(VICTIM_NO_RELRO)

# Compare RELRO protection levels
compare: $(GOT_INSPECTOR) $(VICTIM_NO_RELRO) $(VICTIM_PARTIAL) $(VICTIM_FULL)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  COMPARING RELRO PROTECTION LEVELS"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> NO RELRO (most vulnerable):"
	@readelf -l $(VICTIM_NO_RELRO) 2>/dev/null | grep -E "GNU_RELRO|BIND_NOW" || echo "  No RELRO protection"
	@echo ""
	@echo ">>> PARTIAL RELRO (default):"
	@readelf -l $(VICTIM_PARTIAL) 2>/dev/null | grep -E "GNU_RELRO|BIND_NOW" || echo "  No GNU_RELRO"
	@echo ""
	@echo ">>> FULL RELRO (most secure):"
	@readelf -l $(VICTIM_FULL) 2>/dev/null | grep -E "GNU_RELRO|BIND_NOW" || echo "  No GNU_RELRO"
	@readelf -d $(VICTIM_FULL) 2>/dev/null | grep -E "FLAGS|NOW" || true
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  DETAILED ANALYSIS"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Checking each binary with GOT inspector:"
	@echo ""
	./$(GOT_INSPECTOR) ./$(VICTIM_NO_RELRO) 2>&1 | grep -A5 "RELRO PROTECTION"
	@echo ""
	./$(GOT_INSPECTOR) ./$(VICTIM_PARTIAL) 2>&1 | grep -A5 "RELRO PROTECTION"
	@echo ""
	./$(GOT_INSPECTOR) ./$(VICTIM_FULL) 2>&1 | grep -A5 "RELRO PROTECTION"

# Show GOT entries using objdump
show-got: $(VICTIM_NO_RELRO)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  GOT ENTRIES (via objdump)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	objdump -R $(VICTIM_NO_RELRO)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  PLT ENTRIES (via objdump)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	objdump -d -j .plt $(VICTIM_NO_RELRO)

clean:
	rm -f $(VICTIM_NO_RELRO) $(VICTIM_PARTIAL) $(VICTIM_FULL)
	rm -f $(GOT_HIJACK) $(GOT_INSPECTOR)
	@echo "[+] Cleaned"
