#!/usr/bin/env python3
"""
ELF PT_INTERP Patcher - Educational POC
Demonstrates how to modify the dynamic linker path in ELF binaries
"""

import struct
import sys
import os
from pathlib import Path

class ELFPatcher:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.elf_data = None
        
    def read_elf(self):
        with open(self.binary_path, 'rb') as f:
            self.elf_data = bytearray(f.read())
    
    def write_elf(self, output_path):
        with open(output_path, 'wb') as f:
            f.write(self.elf_data)
        os.chmod(output_path, 0o755)
    
    def find_interp_section(self):
        if len(self.elf_data) < 64:
            raise ValueError("Invalid ELF file")
        
        ei_class = self.elf_data[4]
        if ei_class == 1:  # 32-bit
            ehdr_size = 52
            phdr_size = 32
        else:  # 64-bit
            ehdr_size = 64
            phdr_size = 56
        
        e_phoff = struct.unpack('<Q' if ei_class == 2 else '<I', 
                               self.elf_data[32:40] if ei_class == 2 else self.elf_data[28:32])[0]
        e_phnum = struct.unpack('<H', self.elf_data[56:58] if ei_class == 2 else self.elf_data[44:46])[0]
        
        for i in range(e_phnum):
            phdr_offset = e_phoff + i * phdr_size
            p_type = struct.unpack('<I', self.elf_data[phdr_offset:phdr_offset + 4])[0]
            
            if p_type == 3:  # PT_INTERP
                if ei_class == 2:  # 64-bit
                    p_offset = struct.unpack('<Q', self.elf_data[phdr_offset + 8:phdr_offset + 16])[0]
                    p_filesz = struct.unpack('<Q', self.elf_data[phdr_offset + 32:phdr_offset + 40])[0]
                else:  # 32-bit
                    p_offset = struct.unpack('<I', self.elf_data[phdr_offset + 4:phdr_offset + 8])[0]
                    p_filesz = struct.unpack('<I', self.elf_data[phdr_offset + 16:phdr_offset + 20])[0]
                
                return p_offset, p_filesz
        
        return None, None
    
    def patch_interpreter(self, new_interp_path):
        interp_offset, interp_size = self.find_interp_section()
        
        if interp_offset is None:
            print("Error: PT_INTERP segment not found")
            return False
        
        current_interp = self.elf_data[interp_offset:interp_offset + interp_size - 1].decode('utf-8')
        print(f"Current interpreter: {current_interp}")
        
        new_interp_bytes = new_interp_path.encode('utf-8') + b'\x00'
        
        if len(new_interp_bytes) > interp_size:
            print(f"Error: New interpreter path too long ({len(new_interp_bytes)} > {interp_size})")
            return False
        
        self.elf_data[interp_offset:interp_offset + len(new_interp_bytes)] = new_interp_bytes
        
        if len(new_interp_bytes) < interp_size:
            padding_size = interp_size - len(new_interp_bytes)
            self.elf_data[interp_offset + len(new_interp_bytes):interp_offset + interp_size] = b'\x00' * padding_size
        
        print(f"Patched interpreter to: {new_interp_path}")
        return True

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 patch_interp.py <input_binary> <output_binary> <new_interpreter>")
        print("Example: python3 patch_interp.py /bin/ls ./patched_ls ./malicious_loader")
        sys.exit(1)
    
    input_binary = sys.argv[1]
    output_binary = sys.argv[2] 
    new_interpreter = sys.argv[3]
    
    if not os.path.exists(input_binary):
        print(f"Error: Input binary {input_binary} not found")
        sys.exit(1)
    
    print(f"Patching {input_binary} -> {output_binary}")
    print(f"New interpreter: {new_interpreter}")
    
    patcher = ELFPatcher(input_binary)
    patcher.read_elf()
    
    if patcher.patch_interpreter(new_interpreter):
        patcher.write_elf(output_binary)
        print(f"Successfully created patched binary: {output_binary}")
    else:
        print("Failed to patch binary")
        sys.exit(1)

if __name__ == "__main__":
    main()