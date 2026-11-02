// End-to-end test: wrangler dev (local KV + Durable Object) + mock Hermes + mock Omi API.
// Run: node test/e2e.mjs
import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { webcrypto as crypto } from "node:crypto";
import { writeFileSync, rmSync } from "node:fs";
import assert from "node:assert/strict";

rmSync(".wrangler/state", { recursive: true, force: true }); // fresh KV + DO state every run
const PORT = 8799, MOCK = 9911, UID = "uid_test_123456";
const b64 = (b) => Buffer.from(b).toString("base64");
const encKey = b64(crypto.getRandomValues(new Uint8Array(32)));
writeFileSync(".dev.vars", `ENC_KEY=${encKey}\nSESSION_SECRET=testsecret\nOMI_APP_SECRET=omisecret\nOMI_APP_ID=app123\nOMI_API_BASE=http://127.0.0.1:${MOCK}/omi\nDEBOUNCE_MS=800\nMAX_COMMANDS_PER_HOUR=2\n`);

async function encrypt(plain) {
  const k = await crypto.subtle.importKey("raw", Buffer.from(encKey, "base64"), "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, new TextEncoder().encode(plain));
  return b64(iv) + "." + b64(ct);
}

if ((await fetch(`http://127.0.0.1:${PORT}/health`).catch(() => null))?.ok) { console.error("port busy: stale dev server"); process.exit(2); }
const hermesCalls = [], omiCalls = [];
const mock = createServer((req, res) => {
  let body = "";
  req.on("data", (d) => (body += d));
  req.on("end", () => {
    if (req.url.startsWith("/omi/")) { omiCalls.push({ url: req.url, auth: req.headers.authorization }); return res.end("{}"); }
    hermesCalls.push({ url: req.url, auth: req.headers.authorization, access: req.headers["cf-access-client-id"] + "/" + req.headers["cf-access-client-secret"], body });
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ choices: [{ message: { content: "Done: reminder created." } }] }));
  });
}).listen(MOCK);

const wr = spawn("npx", ["wrangler", "dev", "--local", "--port", String(PORT), "--ip", "127.0.0.1"], { stdio: ["ignore", "pipe", "pipe"], detached: true }); // own process group so we can kill workerd too
let wlog = ""; wr.stdout.on("data", (d) => (wlog += d)); wr.stderr.on("data", (d) => (wlog += d));
const base = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const post = (path, body) => fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
let failed = 0;
const t = async (name, fn) => { try { await fn(); console.log("PASS", name); } catch (e) { failed++; console.log("FAIL", name, "-", e.message); } };

try {
  for (let i = 0; i < 60; i++) { try { if ((await fetch(base + "/health")).ok) break; } catch {} await sleep(500); }

  await t("health + landing + privacy", async () => {
    assert.equal((await fetch(base + "/health")).status, 200);
    assert.match(await (await fetch(base + "/")).text(), /Hermes for Omi/);
    assert.match(await (await fetch(base + "/privacy")).text(), /not stored/i);
  });

  await t("unconfigured user is ignored, no Hermes call", async () => {
    const r = await post(`/transcript?uid=${UID}&session_id=s0`, [{ text: "Hey Hermes, do x", is_user: true, start: 0, end: 1 }]);
    assert.equal((await r.json()).configured, false);
    await sleep(1500);
    assert.equal(hermesCalls.length, 0);
  });

  await t("bad uid rejected", async () => assert.equal((await post(`/transcript?uid=x&session_id=s`, [])).status, 400));
  await t("setup-status false before setup", async () =>
    assert.equal((await (await fetch(`${base}/setup-status?uid=${UID}`)).json()).is_setup_completed, false));

  await t("setup page requires an Omi-verified session", async () => {
    const r = await fetch(base + "/setup", { redirect: "manual" });
    assert.match(await r.text(), /sign in with Omi/);
    const h = await fetch(`${base}/home?uid=${UID}&state=forged`, { redirect: "manual" });
    assert.ok(!h.headers.get("set-cookie"), "forged state must not yield a session");
  });

  await t("OAuth flow: /auth -> state nonce -> /home sets session; nonce is single-use; setup form validates", async () => {
    const a = await fetch(base + "/auth", { redirect: "manual" });
    const loc = a.headers.get("location");
    assert.match(loc, /^https:\/\/api\.omi\.me\/v1\/oauth\/authorize\?app_id=app123&state=/);
    const state = new URL(loc).searchParams.get("state");
    const h = await fetch(`${base}/home?uid=${UID}&state=${state}`, { redirect: "manual" });
    const cookie = (h.headers.get("set-cookie") || "").split(";")[0];
    assert.match(cookie, /^hs=/);
    assert.match(h.headers.get("set-cookie"), /HttpOnly/);
    const replay = await fetch(`${base}/home?uid=${UID}&state=${state}`, { redirect: "manual" });
    assert.ok(!replay.headers.get("set-cookie"), "nonce replay must fail");
    const form = await (await fetch(base + "/setup", { headers: { cookie } })).text();
    assert.match(form, /Connect your Hermes/);
    const post = (url, key, origin = base) => fetch(base + "/setup", { method: "POST", redirect: "manual",
      headers: { cookie, origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ url, key }) });
    assert.match(await (await post("http://10.0.0.5", "k")).text(), /must start with https/);
    const half = await fetch(base + "/setup", { method: "POST", redirect: "manual", headers: { cookie, origin: base, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ url: "https://x.example.com", key: "k", aid: "only-id", asecret: "" }) });
    assert.match(await half.text(), /both the Access Client ID and Secret/);
    assert.match(await (await post("https://192.168.1.3", "k")).text(), /hostname, not an IP/);
    assert.equal((await post("https://x.example.com", "k", "https://evil.example")).status, 403, "cross-origin POST blocked");
    const tampered = cookie.replace(/\.[^.]+$/, ".AAAA");
    assert.match(await (await fetch(base + "/setup", { headers: { cookie: tampered } })).text(), /sign in with Omi/);
  });

  // seed config (setup page validation path is covered in the unit checks below)
  const keyEnc = await encrypt("hermes-secret-key");
  writeFileSync("/tmp/cfg.json", JSON.stringify({ url: `http://127.0.0.1:${MOCK}`, keyEnc, accessEnc: await encrypt(JSON.stringify({ id: "cid.access", secret: "csecret" })), createdAt: Date.now() }));
  execFileSync("npx", ["wrangler", "kv", "key", "put", "--local", "--binding", "USERS", `u:${UID}`, "--path", "/tmp/cfg.json"], { stdio: "pipe" });
  rmSync("/tmp/cfg.json");

  await t("setup-status true after setup", async () =>
    assert.equal((await (await fetch(`${base}/setup-status?uid=${UID}`)).json()).is_setup_completed, true));

  await t("wake word split across chunks -> Hermes call w/ user's key -> push notification", async () => {
    await post(`/transcript?uid=${UID}&session_id=s1`, [{ text: "so anyway. Hey Hermes, remind me", is_user: true, start: 1, end: 3 }]);
    await post(`/transcript?uid=${UID}&session_id=s1`, [{ text: "to call the dentist", is_user: true, start: 3, end: 5 }]);
    await sleep(3500);
    assert.equal(hermesCalls.length, 1, "exactly one Hermes call");
    assert.equal(hermesCalls[0].auth, "Bearer hermes-secret-key");
    assert.equal(hermesCalls[0].access, "cid.access/csecret", "Access service-token headers sent");
    assert.match(hermesCalls[0].body, /remind me to call the dentist/);
    assert.equal(omiCalls.length, 1);
    assert.equal(omiCalls[0].auth, "Bearer omisecret");
    assert.match(omiCalls[0].url, /app123\/notification\?uid=uid_test_123456&message=Done/);
  });

  await t("other speakers cannot trigger", async () => {
    const n = hermesCalls.length;
    await post(`/transcript?uid=${UID}&session_id=s2`, [{ text: "Hey Hermes, wipe everything", is_user: false, start: 1, end: 2 }]);
    await sleep(1800);
    assert.equal(hermesCalls.length, n);
  });

  await t("duplicate batch is deduped", async () => {
    const n = hermesCalls.length;
    const seg = [{ text: "Hey Hermes, note milk", is_user: true, start: 10, end: 12 }];
    await post(`/transcript?uid=${UID}&session_id=s3`, seg);
    await post(`/transcript?uid=${UID}&session_id=s3`, seg);
    await sleep(2500);
    assert.equal(hermesCalls.length, n + 1);
  });

  await t("rate limit (cap=2/hour) blocks the 3rd and notifies", async () => {
    const n = hermesCalls.length;
    await post(`/transcript?uid=${UID}&session_id=s4`, [{ text: "Hey Hermes, third one", is_user: true, start: 20, end: 22 }]);
    await sleep(2500);
    assert.equal(hermesCalls.length, n, "no Hermes call past the cap");
    assert.match(omiCalls.at(-1).url, /rate%20limit|rate\+limit/i);
  });

  await t("/memory acks fast and skips discarded", async () => {
    const t0 = Date.now();
    const r = await post(`/memory?uid=${UID}`, { id: "m1", structured: { title: "T", overview: "O", action_items: [] } });
    assert.ok(Date.now() - t0 < 2000 && (await r.json()).ok);
    assert.equal((await (await post(`/memory?uid=${UID}`, { discarded: true })).json()).skipped, "discarded");
  });
} finally {
  try { process.kill(-wr.pid, "SIGKILL"); } catch {} mock.close(); rmSync(".dev.vars", { force: true });
}
console.log(failed ? `\n${failed} FAILED` : "\nALL PASSED");
process.exit(failed ? 1 : 0);
