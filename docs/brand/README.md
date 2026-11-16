# JANUS brand files

A draft wordmark and lockup, made from what the product already uses. Not final: a designer may replace them.

| File | Use |
|---|---|
| `janus-lockup.svg` | Mark and wordmark, for dark backgrounds |
| `janus-lockup-on-light.svg` | Mark and wordmark, for light backgrounds |
| `janus-wordmark.svg` | Wordmark alone, for dark backgrounds |
| `janus-wordmark-on-light.svg` | Wordmark alone, for light backgrounds |
| `preview.png` | All four, as rendered |

- **Letters:** outlines of IBM Plex Sans Condensed SemiBold (SIL Open Font License 1.1), the app's own typeface, with
  0.16 em letter-spacing. They're paths, so the files display the same without the font installed.
- **Mark:** the app's mask (`web/public/nightfall-mark.svg`), unchanged. On light backgrounds its outline is `#17191D`.
- **Colours:** off-white `#E8E8EC`, ink `#17191D`, mark red `#C43B43`.
- **Clear space:** the files include 12 units of padding; keep at least that much around them.
- **To rebuild:** `python docs/brand/build_wordmark.py <IBM Plex Sans Condensed SemiBold font file> docs/brand`
  (needs `fonttools`, and `brotli` for a `.woff2` file).
