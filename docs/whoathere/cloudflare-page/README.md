# WhoaThere Thread Cloudflare Page

This directory is the deployable Cloudflare Pages bundle for the sanitized Codex thread export.

- `index.html` is generated from `../design-whoathere-architecture-thread.html`.
- `_worker.js` enforces Basic Auth before serving assets.
- Username: `whoathere`
- Password: the worker fallback is the user-provided share password. For a harder production setup, set `BASIC_AUTH_PASSWORD` as a Pages secret and remove the fallback before sharing beyond the intended audience.

Deploy:

```bash
npx wrangler pages deploy docs/whoathere/cloudflare-page --project-name whoathere-architecture-thread --branch main
```
