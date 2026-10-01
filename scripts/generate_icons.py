import os
import struct
import zlib

def create_png_icon(size: int, filename: str):
    """Generates a clean dark cybersecurity shield PNG icon without external heavy imaging deps."""
    width = size
    height = size
    raw_data = bytearray()
    
    center_x = width / 2.0
    center_y = height / 2.0
    radius = (min(width, height) / 2.0) - 1.0

    for y in range(height):
        raw_data.append(0)  # PNG filter type 0 (None)
        for x in range(width):
            dx = x - center_x
            dy = y - center_y
            dist = (dx * dx + dy * dy) ** 0.5
            
            # Draw rounded shield-like badge
            if dist <= radius:
                # Cyan to Deep Blue gradient
                factor = (y / float(height))
                r = int(14 + (6 * factor))
                g = int(165 - (70 * factor))
                b = int(233 + (15 * factor))
                a = 255
                # Center shield core highlight
                if abs(dx) < (radius * 0.45) and (dy > -radius * 0.5 and dy < radius * 0.5):
                    r = int(240 * (1 - factor))
                    g = 255
                    b = 255
            else:
                r, g, b, a = 0, 0, 0, 0
            
            raw_data.extend([r, g, b, a])

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) +
            chunk_type +
            data +
            struct.pack(">I", zlib.crc32(chunk_type + data) & 0xffffffff)
        )

    png_header = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr = chunk(b"IHDR", ihdr_data)
    idat = chunk(b"IDAT", zlib.compress(bytes(raw_data), 9))
    iend = chunk(b"IEND", b"")

    with open(filename, "wb") as f:
        f.write(png_header + ihdr + idat + iend)

assets_dir = "extension/assets"
os.makedirs(assets_dir, exist_ok=True)
for s in [16, 32, 48, 128]:
    create_png_icon(s, os.path.join(assets_dir, f"icon{s}.png"))
print("Generated extension icons successfully.")
