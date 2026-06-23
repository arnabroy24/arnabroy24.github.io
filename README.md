# Arnab Roy Portfolio

A lightweight static portfolio built for GitHub Pages. No build tools, paid hosting, or server-side code required.

## Publish on GitHub Pages

1. Create a **public** GitHub repository named `YOUR-GITHUB-USERNAME.github.io`.
   - Example: `arnabroy.github.io`.
2. Upload the contents of this folder to the repository root. `index.html` must remain at the root.
3. In the repository, open **Settings → Pages**.
4. Under **Build and deployment**, select **Deploy from a branch**.
5. Choose `main` and `/(root)`, then select **Save**.
6. GitHub will publish the site at `https://YOUR-GITHUB-USERNAME.github.io`.

## Recommended personalizations

- Add a headshot only if you want one. The current version intentionally uses a clean editorial security design without a photo.
- Replace the email, phone number, and LinkedIn URL in `index.html` if those change.
- Add a resume PDF under `assets/` and add a link to it in the hero section when you are ready.
- Add a custom domain later through GitHub Pages settings if you decide to purchase one.

## Local preview

Double-click `index.html` to open it in a browser. No installation is needed.

## Supply-chain research automation

The repository includes a daily GitHub Actions workflow that reads supply-chain security RSS feeds, clusters related coverage, and opens a pull request with synthesized research posts.

Required setup:

1. Add a GitHub repository secret named `OPENAI_API_KEY`.
2. Optional: add a repository variable named `OPENAI_MODEL` to override the default model.
3. Review and merge the pull request opened by the workflow before publishing new writeups.

Main files:

- `.github/workflows/supply-chain-intel.yml` schedules the daily run.
- `scripts/supply_chain_intel.py` fetches feeds, clusters incidents, calls OpenAI, and renders static HTML.
- `.data/supply-chain-intel/state.json` tracks prior source URLs and incident clusters.
- `research.html` lists published writeups.
