"""Builds the JANUS wordmark and lockups as outlined SVG (no font needed to display them)."""
import sys
from pathlib import Path
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen
from fontTools.ttLib import TTFont

font_path, out = sys.argv[1], Path(sys.argv[2])
font = TTFont(font_path)
gs, cmap, upm = font.getGlyphSet(), font.getBestCmap(), font["head"].unitsPerEm
cap = font["OS/2"].sCapHeight
TRACK = 0.16 * upm  # letter-spacing

def word(text, size, x0, baseline):
    """SVG path data for text at cap-height `size`, left edge x0, on `baseline`."""
    k = size / cap
    pen = SVGPathPen(gs, ntos=lambda v: f"{v:.2f}".rstrip("0").rstrip("."))
    x, first = 0.0, True
    names = [cmap[ord(c)] for c in text]
    bp = BoundsPen(gs); gs[names[0]].draw(bp); lsb = bp.bounds[0]
    for n in names:
        g = gs[n]
        g.draw(TransformPen(pen, (k, 0, 0, -k, x0 + (x - lsb) * k, baseline)))
        x += g.width + TRACK
    bp = BoundsPen(gs); gs[names[-1]].draw(bp)
    right = x0 + (x - TRACK - gs[names[-1]].width + bp.bounds[2] - lsb) * k
    return pen.getCommands(), right

MARK = """<g fill="none" stroke="{line}" stroke-width="7" stroke-linejoin="round"><path d="M34 72 25 17 72 43 Q100 31 128 43 L175 17 166 72 Q184 112 151 145 Q127 166 100 169 Q73 166 49 145 Q16 112 34 72Z"/></g><path fill="#C43B43" d="M35 69 70 57 91 78 100 94 109 78 130 57 165 69 151 108 119 119 100 106 81 119 49 108Z"/><g fill="#17191D"><path d="m49 82 33-6 12 20-16 9-24-6Z"/><path d="m151 82-33-6-12 20 16 9 24-6Z"/></g><g fill="#F1F1F1"><path d="m66 88 17-3-5 9Z"/><path d="m134 88-17-3 5 9Z"/></g><path fill="{line}" d="m91 127 9-8 9 8-9 8Z"/>"""
NOTE = "<!-- JANUS wordmark. Letters are outlines of IBM Plex Sans Condensed SemiBold (SIL Open Font License 1.1). Built by docs/brand/build_wordmark.py. -->"

def save(name, body, w, h):
    (out / name).write_text(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w:g} {h:g}" role="img" aria-label="JANUS">\n{NOTE}\n{body}\n</svg>\n')

for suffix, ink in (("", "#E8E8EC"), ("-on-light", "#17191D")):
    # Wordmark alone: cap height 72, 12 clear space around.
    d, right = word("JANUS", 72, 12, 84)
    save(f"janus-wordmark{suffix}.svg", f'<path fill="{ink}" d="{d}"/>', round(right + 12), 96)
    # Lockup: mark (200x180 scaled to 0.6 = 120x108) then the wordmark, centred on the mark.
    d, right = word("JANUS", 60, 150, 96)
    mark = MARK.format(line=ink if suffix else "#E8E9EB")
    save(f"janus-lockup{suffix}.svg",
         f'<g transform="translate(12 12) scale(0.6)">{mark}</g>\n<path fill="{ink}" d="{d}"/>',
         round(right + 12), 132)
