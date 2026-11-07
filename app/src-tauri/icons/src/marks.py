"""Draw Vigil's mark: one spiral arm of dots that grow and brighten outward.

Writes, next to this file:
  icon.svg         the app icon, 1024 px, the mark on a dark rounded square
  mark.svg         the tray mark, 24 px, in currentColor
  mark-failed.svg  the tray mark left unfinished (its first 8 of 13 dots), for a failed sweep

Run: uv run --no-project python3 marks.py

The PNGs one level up are rendered from these SVGs with headless Chrome
(--screenshot --default-background-color=00000000), then `sips -z` to size: icon.png at
512 px, tray-*.png at 44 px (22 pt at 2x). tray-clean and tray-failed stay black, as macOS
template images; the others fill mark.svg with sweeping #6e9bff, low #6f7f99,
medium #e8a923 and high #ff5a52.
"""

import math
import pathlib

HERE = pathlib.Path(__file__).parent

# The dark rounded square behind the app mark, drawn to macOS's icon grid (824 px of 1024).
BACKGROUND = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024"><defs>'
    '<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">'
    '<stop offset="0" stop-color="#262a33"/><stop offset="1" stop-color="#0e1014"/>'
    "</linearGradient>"
    '<linearGradient id="rim" x1="0" y1="0" x2="0" y2="1">'
    '<stop offset="0" stop-color="#fff" stop-opacity=".22"/>'
    '<stop offset=".5" stop-color="#fff" stop-opacity=".04"/>'
    '<stop offset="1" stop-color="#fff" stop-opacity=".08"/>'
    "</linearGradient></defs>"
    '<rect x="100" y="100" width="824" height="824" rx="185" fill="url(#bg)"/>'
    '<rect x="101.5" y="101.5" width="821" height="821" rx="183.5" fill="none" '
    'stroke="url(#rim)" stroke-width="3"/>'
)

# The tray mark's dots; the failed mark keeps this many of them.
FAILED_DOTS = 8


def arm(n, turns, radius, rmin, rmax, start):
    """Return n dots (x, y, r, t) along one spiral arm, t running from start to 1."""
    dots = []
    for i in range(n):
        t = start + (1 - start) * i / (n - 1)
        angle = turns * 2 * math.pi * t - math.pi / 2
        dots.append(
            (
                12 + radius * t * math.cos(angle),
                12 + radius * t * math.sin(angle),
                rmin + (rmax - rmin) * t,
                t,
            )
        )
    return dots


def centred(dots, size=24):
    """Shift the dots so their bounding box sits in the middle of a size-by-size box."""
    xs = [x - r for x, _, r, _ in dots] + [x + r for x, _, r, _ in dots]
    ys = [y - r for _, y, r, _ in dots] + [y + r for _, y, r, _ in dots]
    dx = size / 2 - (min(xs) + max(xs)) / 2
    dy = size / 2 - (min(ys) + max(ys)) / 2
    return [(x + dx, y + dy, r, t) for x, y, r, t in dots]


def lerp(c1, c2, t):
    """Mix two #rrggbb colours, t=0 giving c1."""
    a = [int(c1[i : i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i : i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(a[i] + (b[i] - a[i]) * t):02x}" for i in range(3))


def circles(dots, fill):
    return "".join(
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" fill="{fill(t)}"/>' for x, y, r, t in dots
    )


def tray(dots):
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' + dots + "</svg>\n"


def main():
    # The app mark has more, smaller dots than the tray mark, which must read at 22 pt.
    app = centred(arm(26, 1.8, 9.8, 0.22, 1.55, start=0.06))
    mark = centred(arm(13, 1.55, 9.9, 0.55, 1.95, start=0.1))

    dots = circles(app, lambda t: lerp("#5b84f0", "#f2f5fb", t**0.8))
    scaled = '<g transform="translate(512 512) scale(27) translate(-12 -12)">'
    (HERE / "icon.svg").write_text(BACKGROUND + scaled + dots + "</g></svg>\n")

    (HERE / "mark.svg").write_text(tray(circles(mark, lambda _: "currentColor")))
    failed = circles(mark[:FAILED_DOTS], lambda _: "currentColor")
    (HERE / "mark-failed.svg").write_text(tray(failed))


if __name__ == "__main__":
    main()
