// Run: node --test test/unit.test.mjs  (Node 24 strips TS types natively)
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateHermesUrl, WAKE } from "../src/util.ts";

test("accepts public https hostnames", () => {
  assert.deepEqual(validateHermesUrl("https://hermes.example.com/"), { ok: true, url: "https://hermes.example.com" });
  assert.equal(validateHermesUrl("https://a.example.com:443/api/").url, "https://a.example.com/api");
});
test("rejects unsafe targets", () => {
  for (const bad of ["http://hermes.example.com", "https://127.0.0.1", "https://192.168.1.3", "https://localhost", "https://[::1]",
    "https://nas.local", "https://example.com:6789", "https://user:pw@example.com", "https://intranet", "https://x.chillygeek.com", "ftp://x.com", "nope"])
    assert.equal(validateHermesUrl(bad).ok, false, bad);
});
test("wake phrase + mishearings", () => {
  for (const s of ["Hey Hermes, remind me", "hay hermis remind me", "okay Hermes remind me", "Hey, Hermes! remind me", "hi her mes remind me"])
    assert.match(WAKE.exec(s)?.[1] ?? "", /remind me/, s);
  assert.equal(WAKE.exec("the god hermes was fast"), null);
});
