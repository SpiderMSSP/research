# Symbol Versioning Attacks POC - Makefile
#
# Usage:
#   make              - Build all components
#   make demo         - Run all demonstrations
#   make explore      - Explore symbol versions in loaded libraries
#   make hijack       - Demonstrate version hijacking via LD_PRELOAD
#   make show-versions - Show glibc version requirements
#   make clean        - Remove built files

CC = gcc
CFLAGS = -Wall -Wextra -g

# Targets
EXPLORER = version_explorer
VICTIM = victim
VERSIONED_LIB = libversioned.so
EVIL_LIB = libevil_versioned.so

.PHONY: all clean demo explore hijack show-versions show-libc-versions

all: $(EXPLORER) $(VICTIM) $(VERSIONED_LIB) $(EVIL_LIB)

# ═══════════════════════════════════════════════════════════════════════════
# BUILD TARGETS
# ═══════════════════════════════════════════════════════════════════════════

$(EXPLORER): version_explorer.c
	$(CC) $(CFLAGS) -o $@ $< -ldl
	@echo "[+] Built: $@ (symbol versioning explorer)"

$(VICTIM): victim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $@"

# Library with versioned symbols
$(VERSIONED_LIB): versioned_lib.c versioned_lib.map
	$(CC) -shared -fPIC -Wl,--version-script=versioned_lib.map -o $@ versioned_lib.c
	@echo "[+] Built: $@ (library with versioned symbols)"

# Evil library for hijacking
$(EVIL_LIB): evil_versioned.c
	$(CC) -shared -fPIC -o $@ $< -ldl
	@echo "[+] Built: $@ (version hijacking library)"

# ═══════════════════════════════════════════════════════════════════════════
# DEMONSTRATION TARGETS
# ═══════════════════════════════════════════════════════════════════════════

demo: all explore show-versions hijack
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  ALL DEMONSTRATIONS COMPLETE"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Hijack log:"
	@cat /tmp/version_hijack_log.txt 2>/dev/null || echo "(no log)"

# Explore symbol versions in loaded libraries
explore: $(EXPLORER)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  EXPLORING SYMBOL VERSIONS"
	@echo "════════════════════════════════════════════════════════════════"
	./$(EXPLORER)

# Show version requirements with readelf
show-versions: $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  VICTIM'S VERSION REQUIREMENTS (via readelf)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Version requirements (VERNEED):"
	@readelf -V $(VICTIM) 2>/dev/null | head -40 || echo "(readelf not available)"
	@echo ""
	@echo ">>> Symbol versions used:"
	@objdump -T $(VICTIM) 2>/dev/null | grep GLIBC | head -20 || echo "(objdump not available)"

# Demonstrate version hijacking
hijack: $(VICTIM) $(EVIL_LIB)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 1: VICTIM RUNNING NORMALLY"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	SECRET_API_KEY="sk-secret-12345" ./$(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  STEP 2: VICTIM WITH VERSION HIJACKER (LD_PRELOAD)"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	SECRET_API_KEY="sk-secret-12345" LD_PRELOAD=./$(EVIL_LIB) ./$(VICTIM)

# Show glibc versions on this system
show-libc-versions:
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  GLIBC VERSION INFORMATION"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> libc version:"
	@ldd --version 2>&1 | head -1 || echo "(ldd not available)"
	@echo ""
	@echo ">>> Versions provided by libc.so.6:"
	@objdump -T /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | grep "GLIBC_" | \
		sed 's/.*GLIBC_/GLIBC_/' | cut -d' ' -f1 | sort -u | head -20 || \
		echo "(objdump not available)"
	@echo ""
	@echo ">>> realpath versions in libc:"
	@objdump -T /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | grep realpath || \
		echo "(not found)"

# Show versioned library symbols
show-versioned-lib: $(VERSIONED_LIB)
	@echo ""
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  VERSIONED LIBRARY SYMBOLS"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo ">>> Version definitions:"
	@readelf -V $(VERSIONED_LIB) 2>/dev/null || echo "(readelf not available)"
	@echo ""
	@echo ">>> Exported symbols with versions:"
	@objdump -T $(VERSIONED_LIB) 2>/dev/null | grep -v "\\*UND\\*" || \
		echo "(objdump not available)"

clean:
	rm -f $(EXPLORER) $(VICTIM) $(VERSIONED_LIB) $(EVIL_LIB)
	rm -f /tmp/version_hijack_log.txt
	@echo "[+] Cleaned"
