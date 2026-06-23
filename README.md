# Arnab Roy Portfolio

Static GitHub Pages portfolio for Arnab Roy, focused on application security, DevSecOps, and software supply-chain security.

The site is intentionally lightweight: plain HTML, CSS, and JavaScript with no build step. It includes a portfolio homepage, a supply-chain research notebook, and a scheduled workflow that can create reviewable research updates from security RSS feeds.

## Site Structure

- `index.html` - portfolio homepage
- `research.html` - supply-chain research notebook index
- `research/posts/` - generated research note pages
- `styles.css` - site styling
- `script.js` - mobile navigation and footer year behavior
- `robots.txt` and `sitemap.xml` - basic search indexing metadata

## Research Automation

The repository includes a daily GitHub Actions workflow for supply-chain research notes. It checks selected AppSec RSS feeds, groups related coverage into incidents, and opens a pull request with a single synthesized note per attack or campaign.

Automation files:

- `.github/workflows/supply-chain-intel.yml`
- `scripts/supply_chain_intel.py`
- `.data/supply-chain-intel/state.json`

The workflow is review-gated by design: generated notes are proposed through pull requests rather than committed directly to the live site.

## Local Preview

Open `index.html` directly in a browser. No local server is required for the current static site.
