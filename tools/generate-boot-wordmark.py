from pathlib import Path
from PIL import Image
import hashlib
src = Path('assets/boot-wordmark.png')
dst = Path('kernel/src/graphics/boot_wordmark.inc')
image = Image.open(src).convert('RGB')
assert image.size == (556, 69)
raw = image.tobytes()
header = (
    '// Exact RGB pixels from assets/boot-wordmark.png. Regenerate with tools/generate-boot-wordmark.py.\n'
    f'// Source SHA-256: {hashlib.sha256(src.read_bytes()).hexdigest()}\n'
    'constexpr u64 kBootWordmarkWidth = 556;\n'
    'constexpr u64 kBootWordmarkHeight = 69;\n'
    'constexpr u8 kBootWordmarkRgb[] = {\n'
)
with dst.open('w', encoding='ascii', newline='\n') as output:
    output.write(header)
    for index in range(0, len(raw), 24):
        output.write('    ' + ', '.join(f'0x{value:02X}' for value in raw[index:index + 24]) + ',\n')
    output.write('};\n')
print(len(raw), dst.stat().st_size)
