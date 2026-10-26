# Deploying vexproof.dev

The landing page (`site/index.html`) is served at `https://vexproof.dev/` and the docs (`site/docs/index.html`) at `https://vexproof.dev/docs/`. Everything in `site/` is static HTML; there is no build step and no server.

## One-time setup

1. Push this repository to GitHub as a **public** repository in the `pentakis-io` organization. GitHub Pages is free for public repositories.
2. In the repository, open **Settings → Pages** and set **Source** to **GitHub Actions**.
3. At the registrar for `vexproof.dev`, add these DNS records:

| Type | Name | Value |
|---|---|---|
| A | `@` | `185.199.108.153` |
| A | `@` | `185.199.109.153` |
| A | `@` | `185.199.110.153` |
| A | `@` | `185.199.111.153` |
| AAAA | `@` | `2606:50c0:8000::153` |
| AAAA | `@` | `2606:50c0:8001::153` |
| AAAA | `@` | `2606:50c0:8002::153` |
| AAAA | `@` | `2606:50c0:8003::153` |
| CNAME | `www` | `pentakis-io.github.io` |

4. Back in **Settings → Pages**, enter `vexproof.dev` under **Custom domain** and save. No `CNAME` file is needed: GitHub ignores it when a workflow publishes the site.
5. Tick **Enforce HTTPS** once it becomes available. This can take up to 24 hours after the DNS records are in place. A `.dev` address only loads over HTTPS, so the site will not open in a browser until the certificate has been issued.
6. In the organization's settings, verify `vexproof.dev` under **Pages → Verified domains**, so no other GitHub account can claim it.

## Publishing a change

Edit files under `site/` and push to `main`. The `Deploy site` workflow (`.github/workflows/site.yml`) publishes the folder; it can also be run by hand from the **Actions** tab.

## Checking it locally

```
python3 -m http.server --directory site 8080
```

Then open `http://localhost:8080/`.

The DNS values above are from GitHub's documentation ("Managing a custom domain for your GitHub Pages site"). Check them there before entering them, in case they have changed.
