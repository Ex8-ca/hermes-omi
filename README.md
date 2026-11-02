# Hermes for Omi

An [Omi](https://omi.me) wearable app that connects your device to **your own** [Hermes](https://hermes-agent.nousresearch.com) agent.

- **"Hey Hermes, …"** (real-time transcript trigger): the command is sent to your Hermes, and its reply comes back as an Omi push notification. Only the wearer's own voice can trigger it.
- **Conversation summaries** (conversation-created trigger): each finished conversation's summary is passed to your Hermes to save to its long-term memory if worth keeping.

Runs as a Cloudflare Worker + one Durable Object per user. **Nothing about your conversations is stored**: only your Omi user id, your Hermes URL and your Hermes API key (AES-GCM encrypted in KV).

## You need
A Hermes agent with its API server enabled, reachable over public HTTPS on port 443 (for example via a Cloudflare Tunnel). Open the app's setup page from the Omi app, sign in with Omi, and enter the URL and API key.

## Omi app form
| Field | Value |
|---|---|
| Webhook URL | `https://<host>/transcript` (real-time transcript) or `https://<host>/memory` (conversation creation) |
| Auth URL | `https://<host>/auth` |
| App Home URL | `https://<host>/home` |
| Setup Completed URL | `https://<host>/setup-status` |
| Scopes | none needed |

The form's trigger dropdown appears to allow one trigger per app, so create two apps (wake word, memory) sharing this backend if needed. Set `OMI_APP_ID` / `OMI_APP_SECRET` to the wake-word app (the one that sends push replies).

## Deploy
```
npm install
npx wrangler kv namespace create USERS      # paste id into wrangler.toml
npx wrangler secret put ENC_KEY             # openssl rand -base64 32
npx wrangler secret put SESSION_SECRET      # openssl rand -hex 32
npx wrangler secret put OMI_APP_SECRET
# set OMI_APP_ID in wrangler.toml [vars]
npx wrangler deploy
```

## Test
```
npm test                 # unit
node test/e2e.mjs        # wrangler dev + mock Hermes + mock Omi
```

## Security notes
- Omi webhooks carry only an unsigned `uid`. Anyone who knows a uid could send fake transcripts for that user, so commands are phrased to the agent as untrusted input, risky actions require confirmation, and there is a per-user hourly cap.
- The setup page is bound to a real Omi login via a single-use OAuth `state` nonce; cookies are HMAC-signed, HttpOnly, SameSite=Lax; POSTs check `Origin`.
- Hermes URLs must be public https hostnames on port 443 (no IPs, localhost, `.local`).

License: MIT
