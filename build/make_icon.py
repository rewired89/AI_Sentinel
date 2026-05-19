"""
Generate assets/sentinel.ico — the AI Sentinel application icon.
Run once: python build/make_icon.py
Creates a multi-resolution .ico file (16, 32, 48, 64, 128, 256 px)
so Windows shows a sharp icon at every display size.
"""
from pathlib import Path
from PIL import Image, ImageDraw

OUT = Path(__file__).parent.parent / "assets" / "sentinel.ico"
OUT.parent.mkdir(exist_ok=True)


def _draw_shield(size: int, bg_colour: str = "#0f172a") -> Image.Image:
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    m    = size / 64          # scale factor

    # Shield polygon
    pts = [
        (32*m, 3*m),
        (60*m, 14*m),
        (60*m, 36*m),
        (32*m, 61*m),
        (4*m,  36*m),
        (4*m,  14*m),
    ]
    draw.polygon(pts, fill=bg_colour)

    # Inner shield — bright blue fill
    inner_pts = [
        (32*m, 9*m),
        (54*m, 18*m),
        (54*m, 36*m),
        (32*m, 55*m),
        (10*m, 36*m),
        (10*m, 18*m),
    ]
    draw.polygon(inner_pts, fill="#3b82f6")

    # White "S" shape using rectangles — works at all sizes, no font needed
    lx, rx = int(21*m), int(43*m)   # left / right x
    ty, my, by = int(16*m), int(30*m), int(48*m)   # top / mid / bottom y
    bar = max(1, int(5*m))          # bar thickness

    # Top bar
    draw.rectangle([lx, ty, rx, ty+bar], fill="white")
    # Top-left vertical
    draw.rectangle([lx, ty, lx+bar, my], fill="white")
    # Middle bar
    draw.rectangle([lx, my, rx, my+bar], fill="white")
    # Bottom-right vertical
    draw.rectangle([rx-bar, my, rx, by], fill="white")
    # Bottom bar
    draw.rectangle([lx, by-bar, rx, by], fill="white")

    return img


sizes = [16, 32, 48, 64, 128, 256]
frames = [_draw_shield(s) for s in sizes]
frames[0].save(OUT, format="ICO", sizes=[(s, s) for s in sizes],
               append_images=frames[1:])
print(f"Icon written: {OUT}  ({OUT.stat().st_size} bytes)")
