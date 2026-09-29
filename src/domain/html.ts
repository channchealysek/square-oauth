import crypto from 'node:crypto';

export const CALLBACK_CLEANUP_SCRIPT = 'history.replaceState(null,"",location.pathname);';

export const CALLBACK_SCRIPT_HASH = crypto
  .createHash('sha256')
  .update(CALLBACK_CLEANUP_SCRIPT)
  .digest('base64');

export function renderResultPage(input: {
  ok: boolean;
  title: string;
  message: string;
  detail?: string;
  returnUrl?: string;
}): string {
  const tone = input.ok ? 'ok' : 'bad';
  const label = input.ok ? 'Connected' : 'Not connected';
  const detail = input.detail ? `<p>${escapeHtml(input.detail)}</p>` : '';
  const link =
    input.returnUrl && input.returnUrl.startsWith('https://')
      ? `<p><a href="${escapeHtml(input.returnUrl)}" rel="noopener noreferrer">Return to store</a></p>`
      : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex">
<title>${escapeHtml(input.title)}</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f1ea; color: #1f1a17; }
  main { max-width: 32rem; margin: 10vh auto; background: #fff; border-radius: 12px; padding: 2rem; box-shadow: 0 10px 30px rgba(60, 40, 20, 0.08); }
  h1 { font-size: 1.4rem; margin: 0 0 0.75rem; }
  p { line-height: 1.5; }
  a { color: #0b6b4f; font-weight: 600; }
  .ok { color: #0b6b4f; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; font-size: 0.8rem; }
  .bad { color: #8d2b2b; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; font-size: 0.8rem; }
</style>
</head>
<body>
<main>
  <p class="${tone}">${label}</p>
  <h1>${escapeHtml(input.title)}</h1>
  <p>${escapeHtml(input.message)}</p>
  ${detail}
  ${link}
</main>
<script>${CALLBACK_CLEANUP_SCRIPT}</script>
</body>
</html>`;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
