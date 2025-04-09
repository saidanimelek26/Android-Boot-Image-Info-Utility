import sys
import struct
import os
from typing import Dict, Union


BOOT_MAGIC = b"ANDROID!"
BOOT_MAGIC_SIZE = 8
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024

def usage() -> int:
    print("usage: python bootimg_info.py boot.img")
    return 1

def clean_boot_string(data: Union[bytes, int]) -> str:
    """Clean up boot image string fields"""
    if isinstance(data, int):
        return str(data)
    if not isinstance(data, bytes):
        return "(invalid data)"
    try:
        # First try UTF-8
        decoded = data.decode('utf-8', errors='replace').rstrip('\x00')
    except (UnicodeDecodeError, AttributeError):
        # Fall back to latin-1 if UTF-8 fails
        decoded = data.decode('latin-1', errors='replace').rstrip('\x00')
    return decoded

def parse_os_version(hdr_os_ver: int) -> Dict[str, Union[int, str]]:
    """Parse os_version field"""
    a = b = c = y = m = 0
    if hdr_os_ver != 0:
        os_version = hdr_os_ver >> 11
        os_patch_level = hdr_os_ver & 0x7ff
        a = (os_version >> 14) & 0x7f
        b = (os_version >> 7) & 0x7f
        c = os_version & 0x7f
        y = (os_patch_level >> 4) + 2000
        m = os_patch_level & 0xf
    
    return {
        'a': a, 'b': b, 'c': c,
        'year': y, 'month': m,
        'original': hdr_os_ver
    }

def print_os_version(hdr_os_ver: int):
    """Print OS version information"""
    info = parse_os_version(hdr_os_ver)
    if (info['a'] < 128 and info['b'] < 128 and info['c'] < 128 and 
        2000 <= info['year'] < 2128 and 0 < info['month'] <= 12):
        print(f"  os_version                      : {info['a']}.{info['b']}.{info['c']:<5}  ({info['original']:08x})")
        print(f"  (os_patch_level)                : {info['year']}-{info['month']:02d}")
    else:
        print(f"  unused                          : {info['original']:<10}  ({info['original']:08x}")

def print_id(id_data: bytes) -> None:
    """Print ID field as hex"""
    print("  id                              : ", end="")
    for b in id_data[:32]:  # Only show first 32 bytes
        print(f"{b:02x}", end="")
    print("\n")

def parse_boot_header(f) -> Dict:
    """Parse boot image header with flexible structure"""
    # Read magic and basic fields first
    magic = f.read(BOOT_MAGIC_SIZE)
    if magic != BOOT_MAGIC:
        raise ValueError("Invalid boot magic")
    
    # Read the next 10 fields (40 bytes)
    basic_fields = struct.unpack('<IIIIIIIIII', f.read(40))
    
    header = {
        'magic': magic,
        'kernel_size': basic_fields[0],
        'kernel_addr': basic_fields[1],
        'ramdisk_size': basic_fields[2],
        'ramdisk_addr': basic_fields[3],
        'second_size': basic_fields[4],
        'second_addr': basic_fields[5],
        'tags_addr': basic_fields[6],
        'page_size': basic_fields[7],
        'header_version_or_dt_size': basic_fields[8],
        'os_version': basic_fields[9],
    }

    # Read name (16 bytes)
    header['name'] = f.read(BOOT_NAME_SIZE)
    
    # Read cmdline (512 bytes)
    header['cmdline'] = f.read(BOOT_ARGS_SIZE)
    
    # Read id (32 bytes)
    header['id'] = f.read(32)
    
    # Read extra_cmdline (1024 bytes)
    header['extra_cmdline'] = f.read(BOOT_EXTRA_ARGS_SIZE)

    # Try to read remaining fields if they exist
    try:
        # Read recovery_dtbo_size (4 bytes)
        header['recovery_dtbo_size'] = struct.unpack('<I', f.read(4))[0]
        # Read recovery_dtbo_offset (8 bytes)
        header['recovery_dtbo_offset'] = struct.unpack('<Q', f.read(8))[0]
        # Read header_size (4 bytes)
        header['header_size'] = struct.unpack('<I', f.read(4))[0]
    except struct.error:
        # If we can't read these fields, set default values
        header['recovery_dtbo_size'] = 0
        header['recovery_dtbo_offset'] = 0
        header['header_size'] = 0

    # Handle union field
    if header['header_size'] > 0:
        header['header_version'] = header['header_version_or_dt_size']
        header['dt_size'] = 0
    else:
        header['header_version'] = 0
        header['dt_size'] = header['header_version_or_dt_size']

    # Try to read v2+ fields if they exist
    try:
        if header['header_version'] >= 2:
            v2_fields = struct.unpack('<II', f.read(8))
            header['dtb_size'] = v2_fields[0]
            header['dtb_addr'] = v2_fields[1]
        else:
            header['dtb_size'] = 0
            header['dtb_addr'] = 0
    except struct.error:
        header['dtb_size'] = 0
        header['dtb_addr'] = 0

    return header

def print_boot_header_info(header: Dict, magic_offset: int) -> None:
    """Print boot header information"""
    base = header['kernel_addr'] - 0x00008000 if header['kernel_addr'] >= 0x00008000 else 0

    print(f"  magic                           : ANDROID!")
    print(f"  kernel_size                     : {header['kernel_size']:<10}  ({header['kernel_size']:08x})")
    print(f"  kernel_addr                     : 0x{header['kernel_addr']:08x}\n")
    
    print(f"  ramdisk_size                    : {header['ramdisk_size']:<10}  ({header['ramdisk_size']:08x})")
    print(f"  ramdisk_addr                    : 0x{header['ramdisk_addr']:08x}")
    print(f"  second_size                     : {header['second_size']:<10}  ({header['second_size']:08x})")
    print(f"  second_addr                     : 0x{header['second_addr']:08x}\n")
    
    print(f"  tags_addr                       : 0x{header['tags_addr']:08x}")
    print(f"  page_size                       : {header['page_size']:<10}  ({header['page_size']:08x})")
    
    if header['dt_size'] > 0:
        print(f"  dt_size                         : {header['dt_size']:<10}  ({header['dt_size']:08x})")
    else:
        print(f"  header_version                  : {header['header_version']:<10}  ({header['header_version']:08x})")
    
    print_os_version(header['os_version'])
    print(f"\n  name                            : {clean_boot_string(header['name'])}\n")
    print(f"  cmdline                         : {clean_boot_string(header['cmdline'])}\n")
    
    print_id(header['id'])
    print(f"  extra_cmdline                   : {clean_boot_string(header['extra_cmdline'])}\n")

    if header['header_version'] > 0:
        print(f"  recovery_dtbo_size              : {header['recovery_dtbo_size']:<10}  ({header['recovery_dtbo_size']:08x})")
        print(f"  recovery_dtbo_offset            : {header['recovery_dtbo_offset']:<10}  ({header['recovery_dtbo_offset']:016x})")
        print(f"  header_size                     : {header['header_size']:<10}  ({header['header_size']:08x})\n")
    
    if header['header_version'] > 1:
        print(f"  dtb_size                        : {header['dtb_size']:<10}  ({header['dtb_size']:08x})")
        print(f"  dtb_addr                        : 0x{header['dtb_addr']:08x}\n")

    print(" Other:")
    print(f"  magic offset                    : {magic_offset:<10}  ({magic_offset:08x})")
    print(f"  base address                    : 0x{base:08x}\n")
    
    print(f"  kernel offset                   : 0x{header['kernel_addr'] - base:08x}")
    print(f"  ramdisk offset                  : 0x{header['ramdisk_addr'] - base:08x}")
    print(f"  second offset                   : 0x{header['second_addr'] - base:08x}")
    print(f"  tags offset                     : 0x{header['tags_addr'] - base:08x}")
    
    if header['header_version'] > 1 and header['dtb_addr'] != 0:
        print(f"  dtb offset                      : 0x{header['dtb_addr'] - base:08x}")

def main() -> int:
    if len(sys.argv) < 2:
        return usage()

    filename = sys.argv[1]
    if not os.path.exists(filename):
        print("bootimg-info: File not found!")
        return 1

    file_size = os.path.getsize(filename)
    print(f"File size: {file_size} bytes")
    if file_size < BOOT_MAGIC_SIZE:
        print("bootimg-info: File too small to contain a valid header!")
        return 1

    with open(filename, "rb") as f:
        # Find magic header
        magic_offset = None
        for i in range(min(65536, file_size - BOOT_MAGIC_SIZE)):
            f.seek(i)
            magic = f.read(BOOT_MAGIC_SIZE)
            if magic == BOOT_MAGIC:
                magic_offset = i
                break

        if magic_offset is None:
            print("bootimg-info: No boot image magic found!")
            return 1

        print("\nAndroid Boot Image Info Utility")
        print(f"\nPrinting information for \"{filename}\":")
        print("\nheader:")

        f.seek(magic_offset)
        try:
            header = parse_boot_header(f)
            print_boot_header_info(header, magic_offset)
        except Exception as e:
            print(f"Error parsing header: {e}")
            print("The file may be corrupted or not a valid boot image")
            return 1

    print()
    return 0

if __name__ == "__main__":
    sys.exit(main())