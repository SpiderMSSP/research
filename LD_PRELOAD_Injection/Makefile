# LD_PRELOAD Injection POC - Makefile
#
# Usage:
#   make              - Build all components
#   make run          - Run normal victim
#   make run-evil     - Run with evil preload
#   make run-cred     - Run with credential hook
#   make clean        - Remove built files

CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS_SO = -shared -fPIC -ldl

# Targets
VICTIM = victim
EVIL_SO = evil_preload.so
CRED_SO = credential_hook.so

.PHONY: all clean run run-evil run-cred

all: $(VICTIM) $(EVIL_SO) $(CRED_SO)

# Build victim program
$(VICTIM): victim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[+] Built: $(VICTIM)"

# Build evil preload library
$(EVIL_SO): evil_preload.c
	$(CC) $(LDFLAGS_SO) -o $@ $<
	@echo "[+] Built: $(EVIL_SO)"

# Build credential hook library
$(CRED_SO): credential_hook.c
	$(CC) $(LDFLAGS_SO) -o $@ $<
	@echo "[+] Built: $(CRED_SO)"

# Run victim normally
run: $(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════"
	@echo "  Running NORMALLY (no preload)"
	@echo "════════════════════════════════════════════════════════"
	@echo ""
	./$(VICTIM)

# Run with evil preload
run-evil: $(VICTIM) $(EVIL_SO)
	@echo ""
	@echo "════════════════════════════════════════════════════════"
	@echo "  Running with LD_PRELOAD=./$(EVIL_SO)"
	@echo "════════════════════════════════════════════════════════"
	@echo ""
	SECRET_API_KEY="sk-12345-SUPER-SECRET-KEY" LD_PRELOAD=./$(EVIL_SO) ./$(VICTIM)
	@echo ""
	@echo "════════════════════════════════════════════════════════"
	@echo "  Log file contents:"
	@echo "════════════════════════════════════════════════════════"
	@cat /tmp/ld_preload_log.txt 2>/dev/null || echo "(no log)"

# Run with credential hook
run-cred: $(VICTIM) $(CRED_SO)
	@echo ""
	@echo "════════════════════════════════════════════════════════"
	@echo "  Running with credential hook"
	@echo "════════════════════════════════════════════════════════"
	@echo ""
	LD_PRELOAD=./$(CRED_SO) ./$(VICTIM)

clean:
	rm -f $(VICTIM) $(EVIL_SO) $(CRED_SO)
	rm -f /tmp/ld_preload_log.txt /tmp/captured_credentials.txt
	@echo "[+] Cleaned"
