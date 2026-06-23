# arnabroy24.github.io

Source for [arnabroy24.github.io](https://arnabroy24.github.io), my public portfolio and AppSec research notebook.

The site highlights my work in application security, DevSecOps, vulnerability management, and software supply-chain security. It is built as a static GitHub Pages site so the source remains easy to inspect, fork, and audit.

## What This Repo Contains

- A personal portfolio homepage with experience, skills, credentials, and contact links.
- A supply-chain research notebook for package ecosystem incidents and defender-focused analysis.
- A scheduled GitHub Actions workflow that monitors selected security research feeds and opens pull requests for new or updated research notes.

## Repository Map

- `index.html` - main portfolio page
- `research.html` - research notebook index
- `research/posts/` - generated incident notes
- `styles.css` - shared visual system
- `script.js` - mobile navigation behavior
- `scripts/supply_chain_intel.py` - RSS ingestion, clustering, and note generation
- `.github/workflows/supply-chain-intel.yml` - scheduled research workflow
- `.data/supply-chain-intel/state.json` - automation state used to avoid duplicate writeups

## Research Workflow

The research automation checks selected AppSec sources once per day, clusters related coverage, and creates one note per attack or campaign. The goal is to avoid duplicating vendor posts and instead produce a single practical summary focused on exposure, affected ecosystems, and remediation.

Generated changes are proposed through pull requests before they reach the live site.

## Design Notes

The site uses plain HTML, CSS, and JavaScript. There is no frontend framework, package manager, or build step. That keeps deployment simple and makes the portfolio source readable without tooling.
