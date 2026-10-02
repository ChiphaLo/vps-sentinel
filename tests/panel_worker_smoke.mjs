import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, createHmac } from "node:crypto";
// A local SQLite adapter exercises worker SQL and protocol behavior. It is not
// a live Cloudflare/D1 deployment test. Run with Node 24 or newer.
const root = fileURLToPath(new URL("../", import.meta.url));
const { default: worker } = await import("../panel/cloudflare/worker.js");
const sqlite = new DatabaseSync(":memory:");
sqlite.exec(readFileSync(`${root}/panel/cloudflare/schema.sql`, "utf8"));
const DB = {
  prepare(sql) {
    let values = [];
    return {
      bind(...items) {
        values = items;
        return this;
      },
      async run() {
        const result = sqlite.prepare(sql).run(...values);
        return { success: true, meta: result };
      },
      async first(column) {
        const row = sqlite.prepare(sql).get(...values);
        return column ? (row?.[column] ?? null) : (row ?? null);
      },
      async all() {
        return { success: true, results: sqlite.prepare(sql).all(...values) };
      },
    };
  },
  async batch(statements) {
    sqlite.exec("BEGIN");
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      sqlite.exec("COMMIT");
      return results;
    } catch (error) {
      sqlite.exec("ROLLBACK");
      throw error;
    }
  },
};
const env = {
  DB,
  PANEL_TOKEN: "inert-test-admin-token",
  PANEL_SHARED_SECRET: "inert-test-signing-secret",
  PANEL_PUBLIC_PAGES: "nodes,blocks",
  PANEL_ADMIN_PATH: "/manage",
  PANEL_CORS_ORIGIN: "https://console.example.test",
};
let count = 0;
async function test(name, fn) {
  await fn();
  count++;
  console.log(`PASS ${name}`);
}
async function request(path, options = {}, overrides = {}) {
  // The worker logs expected rejected requests. Preserve unexpected errors.
  const logError = console.error;
  console.error = (error) => {
    if (![401, 409].includes(error?.status)) logError(error);
  };
  try {
    return await worker.fetch(
      new Request(`https://panel.example.test${path}`, options),
      { ...env, ...overrides },
    );
  } finally {
    console.error = logError;
  }
}
const auth = { authorization: `Bearer ${env.PANEL_TOKEN}` };
const now = new Date().toISOString();
const payload = {
  schema_version: 2,
  message_id: "worker-lab-message",
  sent_at: now,
  node: {
    node_name: "fixture-node",
    hostname: "192.0.2.10",
    host_id: "private-host-id",
    agent_version: "0.3.1",
    privacy_mode: "strict",
    enabled_features: ["ssh"],
    storage: {},
    metrics: { cpu_percent: 2 },
  },
  scan: {},
  findings: [],
  incidents: [],
  baseline_drifts: [],
  active_blocks: [],
};
function signed(body = JSON.stringify(payload), changes = {}) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = `fixture-node:${crypto.randomUUID()}`;
  const hash = createHash("sha256").update(body).digest("hex");
  const signature = createHmac("sha256", env.PANEL_SHARED_SECRET)
    .update(["POST", "/api/v1/ingest", timestamp, nonce, hash].join("\n"))
    .digest("hex");
  return {
    method: "POST",
    body,
    headers: {
      "x-vps-sentinel-node-name": "fixture-node",
      "x-vps-sentinel-timestamp": timestamp,
      "x-vps-sentinel-nonce": nonce,
      "x-vps-sentinel-body-sha256": hash,
      "x-vps-sentinel-signature": signature,
      ...changes,
    },
  };
}
await test("anonymous settings hide management path and require management auth", async () => {
  const r = await request("/api/v1/settings?path=/manage");
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.role, "public");
  assert.equal(j.admin_path, null);
  assert.equal(j.auth_required, true);
});
await test("authenticated settings expose management path", async () => {
  const r = await request("/api/v1/settings", { headers: auth });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.role, "private");
  assert.equal(j.admin_path, "/manage");
});
await test("invalid admin token rejected", async () => {
  assert.equal(
    (
      await request("/api/v1/nodes", {
        headers: { authorization: "Bearer invalid" },
      })
    ).status,
    401,
  );
});
await test("private detail and writes reject anonymous users", async () => {
  assert.equal((await request("/api/v1/finding?id=missing")).status, 403);
  assert.equal(
    (await request("/api/v1/review", { method: "POST", body: "{}" })).status,
    403,
  );
});
await test("exact CORS origin allowed and foreign origin excluded", async () => {
  for (const [origin, allowed] of [
    ["https://console.example.test", true],
    ["https://foreign.example.test", false],
  ]) {
    const r = await request("/api/v1/settings", {
      method: "OPTIONS",
      headers: { origin },
    });
    assert.equal(r.status, 204);
    assert.equal(
      r.headers.get("access-control-allow-origin"),
      allowed ? origin : null,
    );
    assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  }
});
await test("unsigned ingest rejected", async () => {
  assert.equal(
    (await request("/api/v1/ingest", { method: "POST", body: "{}" })).status,
    401,
  );
});
await test("oversized ingest rejected", async () => {
  assert.equal(
    (
      await request(
        "/api/v1/ingest",
        { method: "POST", body: "12345" },
        { PANEL_MAX_BODY_BYTES: "4" },
      )
    ).status,
    413,
  );
});
await test("stale signature rejected", async () => {
  const r = await request(
    "/api/v1/ingest",
    signed(undefined, { "x-vps-sentinel-timestamp": "1" }),
  );
  assert.equal(r.status, 401);
  assert.equal((await r.json()).error, "signature_timestamp_out_of_window");
});
await test("tampered body rejected", async () => {
  const s = signed();
  s.body += " ";
  const r = await request("/api/v1/ingest", s);
  assert.equal(r.status, 401);
  assert.equal((await r.json()).error, "body_hash_mismatch");
});
await test("forged signature rejected", async () => {
  const r = await request(
    "/api/v1/ingest",
    signed(undefined, { "x-vps-sentinel-signature": "0".repeat(64) }),
  );
  assert.equal(r.status, 401);
  assert.equal((await r.json()).error, "signature_mismatch");
});
const valid = signed();
await test("signed ingest persists real SQLite rows and redacts identity", async () => {
  const r = await request("/api/v1/ingest", valid);
  assert.equal(r.status, 200, await r.clone().text());
  assert.equal((await r.json()).ok, true);
  const row = sqlite.prepare("SELECT * FROM nodes").get();
  assert.equal(row.node_id, "fixture-node");
  assert.equal(row.host_id, "");
  assert.notEqual(row.hostname, "192.0.2.10");
  assert.equal(
    sqlite.prepare("SELECT COUNT(*) AS n FROM heartbeats").get().n,
    1,
  );
});
await test("signed nonce replay rejected", async () => {
  const r = await request("/api/v1/ingest", valid);
  assert.equal(r.status, 409);
  assert.equal((await r.json()).error, "nonce_replay");
});
await test("public node listing hides sensitive identity", async () => {
  const r = await request("/api/v1/nodes");
  assert.equal(r.status, 200, await r.clone().text());
  const text = await r.text();
  assert.ok(!text.includes("private-host-id"));
  assert.ok(!text.includes("192.0.2.10"));
  assert.ok(!text.includes("host_id"));
  assert.ok(!text.includes("hostname"));
  assert.equal(JSON.parse(text).items[0].metrics.cpu_percent, 2);
});
await test("authenticated summary reads persisted state", async () => {
  const r = await request("/api/v1/summary", { headers: auth });
  assert.equal(r.status, 200, await r.clone().text());
  const text = await r.text();
  assert.ok(text.includes("nodes"));
});
console.log(
  JSON.stringify({
    passed: count,
    failed: 0,
    backend: "Node SQLite D1 adapter; no live Cloudflare deployment",
  }),
);
sqlite.close();
