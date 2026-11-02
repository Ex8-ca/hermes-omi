// Pure helpers (no Workers APIs) so they can be unit-tested directly under Node.

/** Only public https hostnames. Workers can't reach private nets, but never rely on that alone. */
export function validateHermesUrl(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return { ok: false, error: "Not a valid URL." };
  }
  if (u.protocol !== "https:") return { ok: false, error: "URL must start with https://" };
  if (u.username || u.password) return { ok: false, error: "No credentials in the URL." };
  if (u.port && u.port !== "443") return { ok: false, error: "Only port 443 is supported. Put Hermes behind a tunnel/proxy on 443." };
  const h = u.hostname.toLowerCase();
  if (/^[\d.]+$/.test(h) || h.includes(":") || h.startsWith("[")) return { ok: false, error: "Use a hostname, not an IP address." };
  if (h === "localhost" || !h.includes(".") || /\.(local|internal|lan|home|corp|localdomain)$/.test(h))
    return { ok: false, error: "Hostname must be publicly resolvable." };
  if (h.endsWith(".chillygeek.com")) return { ok: false, error: "That hostname is not allowed." };
  return { ok: true, url: (u.origin + u.pathname).replace(/\/+$/, "") };
}

export const WAKE = /\b(?:hey|hay|hi|okay|ok)[,.\s]+(?:hermes|hermis|hermies|her\s?mes|hermez)\b[,.:!\s]*(.*)/is;
