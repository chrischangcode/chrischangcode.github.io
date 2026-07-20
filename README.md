# chrischangcode.github.io

Static project sites for [@chrischangcode](https://github.com/chrischangcode),
served from GitHub Pages at <https://chrischangcode.github.io/>.

## Layout

| Path | Project | Source |
| --- | --- | --- |
| `/` | Landing page (`index.html`) | this repo |
| `/aks-security-advisory/` | AKS VHD security-advisory site + feed data | pushed by the `aks-security-advisory` repo's `pages` workflow |

Each sub-directory is an independent static site. Sub-sites whose content is
generated elsewhere (e.g. `aks-security-advisory/`) are **published by that
project's CI** via a write-scoped deploy key — do not edit them here by hand; the
next deploy will overwrite them.

## Adding a new project

1. Create `./<project>/` with the static site (or have the project's CI push into it).
2. Add a card to `index.html`.

`.nojekyll` is present so GitHub Pages serves files verbatim (no Jekyll
processing), which is required for the JSON data and hyphenated paths.
