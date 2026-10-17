const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const ui = path.resolve(__dirname, "../ui");

// Exercise the shipped renderer through its state bridge, without Electron or a
// model connection. IDs must exist in the shipped HTML, including new metrics.
function renderer() {
  const node = (id = "") => ({
    id, textContent: "", value: "", hidden: false, dataset: {}, children: [], handlers: {},
    addEventListener(event, callback) { this.handlers[event] = callback; },
    setAttribute() {}, removeAttribute() {},
    append(child) { this.children.push(child); },
    replaceChildren(fragment) { this.children = fragment.children; },
  });
  const html = fs.readFileSync(path.join(ui, "compression.html"), "utf8");
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => [match[1], node(match[1])]));
  const navigation = ["connection", "usage", "settings"].map((page) => ({ ...node(), dataset: { page } }));
  const get = (id) => { assert.ok(nodes.has(id), `HTML must contain #${id}`); return nodes.get(id); };
  let onState;
  vm.runInNewContext(fs.readFileSync(path.join(ui, "compression.js"), "utf8"), {
    window: {
      lingmouCompression: { onState(callback) { onState = callback; }, environment: () => new Promise(() => {}) },
      addEventListener() {},
    },
    document: {
      getElementById: get,
      querySelectorAll: (selector) => selector === ".page"
        ? ["connection", "usage", "settings"].map((page) => get(`page-${page}`)) : navigation,
      createElement: () => node(), createDocumentFragment: () => node(),
    },
  });
  return {
    get,
    text: (id) => get(id).textContent,
    rows: (id) => get(id).children.map((row) => row.children.map((cell) => cell.textContent)),
    render: (state = {}) => onState({ enabled: true, running: true, request_count: 3,
      usage_scope: { started: true, id: "conversation-a", requests: 3, active_requests: 0 }, ...state }),
  };
}

function usage() {
  return {
    local: { before: 20000, after: 14000, saved: 6000, savings_percent: 30, requests: 3, compressed_requests: 2 },
    official: { input_tokens: 900, output_tokens: 99, total_tokens: 999, cached_input_tokens: 500,
      measured_requests: 2, missing_requests: 1, compression_tokens: null, known_compression_tokens: 200, missing_compression_calls: 1 },
    breakdown: { requests: 3, components: [
      { label: "工具返回", before: 10000, after: 3995, saved: 6005 },
      { label: "工具定义", before: 500, after: 505, saved: -5 },
    ] },
    recent_requests: [
      { request_id: "r1", status: "completed", before: 1000, after: 600, official_input: 610, official_output: 50 },
      { request_id: "r2", status: "failed", before: 100, after: null, official_input: null, official_output: null },
    ],
  };
}

test("shows current conversation compression separately from official and auxiliary usage", () => {
  const view = renderer();
  view.render({ tokens: usage() });
  assert.equal(view.text("compression-saved"), "6,000");
  assert.equal(view.text("compression-percent"), "30%");
  assert.equal(view.text("compression-before"), "20,000");
  assert.equal(view.text("compression-after"), "14,000");
  assert.match(view.text("compression-summary"), /3 次请求 · 2 次输入缩短/);
  assert.equal(view.text("connection-saved"), "6,000 tokens · 本地估算");
  assert.equal(view.text("official-total"), "999");
  assert.equal(view.get("usage-data").hidden, false);
  assert.equal(view.get("usage-empty").hidden, true);
  assert.match(view.text("usage-period"), /旧对话的累计用量不带入/);
  assert.match(view.text("auxiliary-usage"), /200 tokens（已知小计，另有 1 次调用用量未知）/);
  view.get("view-compression").handlers.click();
  assert.equal(view.get("page-usage").hidden, false);
  assert.equal(view.get("page-connection").hidden, true);
});

test("compares components and requests, preserving growth and missing measurements", () => {
  const view = renderer();
  view.render({ tokens: usage() });
  assert.deepEqual(view.rows("component-rows"), [
    ["工具返回", "10,000", "3,995", "6,005"], ["工具定义", "500", "505", "-5"],
  ]);
  assert.deepEqual(view.rows("request-rows"), [
    ["r2", "失败", "100", "—", "—", "—", "—"], ["r1", "已结束", "1,000", "600", "400", "610", "50"],
  ]);
});

test("empty, legacy, and incomplete snapshots show unknown savings instead of zero", () => {
  const view = renderer();
  for (const tokens of [{}, { local: { requests: 0, before: 0, after: 0, saved: 0 } },
    { local: { requests: 1, before: 100, after: null } },
    { local: { requests: 1, before: NaN, after: 0 } }]) {
    view.render({ tokens });
    for (const id of ["compression-saved", "compression-percent", "compression-before", "compression-after"])
      assert.equal(view.text(id), "—");
  }
  assert.equal(view.get("component-rows").children[0].children[0].colSpan, 4);
  assert.equal(view.get("request-rows").children[0].children[0].colSpan, 7);
});

test("known zero savings are displayed and explained, including disabled compression", () => {
  const view = renderer();
  const tokens = { local: { requests: 1, compressed_requests: 0, before: 100, after: 100, saved: 0, savings_percent: 0 } };
  view.render({ tokens });
  assert.equal(view.text("compression-saved"), "0");
  assert.equal(view.text("compression-percent"), "0%");
  assert.match(view.text("compression-hint"), /没有可压缩内容/);
  view.render({ connection: { mode: "off" }, tokens });
  assert.match(view.text("compression-hint"), /当前已关闭压缩/);
  view.render({ tokens: { local: { ...tokens.local, before: 0, after: 0, savings_percent: null } } });
  assert.equal(view.text("compression-before"), "0");
  assert.equal(view.text("compression-percent"), "—");
});

test("polling replaces totals, mode changes preserve totals, and a restart clears them", () => {
  const view = renderer();
  const tokens = usage();
  view.render({ tokens });
  view.render({ tokens });
  assert.equal(view.text("compression-saved"), "6,000");
  view.render({ connection: { mode: "off" }, tokens });
  assert.equal(view.text("compression-saved"), "6,000");
  view.render({ enabled: false, running: false, tokens });
  assert.equal(view.text("compression-saved"), "—");
  assert.equal(view.get("usage-data").hidden, true);
  view.render({ request_count: 0, usage_scope: { started: false }, tokens: {} });
  assert.equal(view.text("compression-saved"), "—");
  assert.match(view.text("compression-summary"), /等待请求/);
});

test("initialization traffic and old snapshots never display token usage before a conversation", () => {
  const view = renderer();
  for (const usage_scope of [undefined, { started: false, requests: 0 }]) {
    view.render({ request_count: 20, tokens: usage(), usage_scope });
    assert.equal(view.get("usage-data").hidden, true);
    assert.equal(view.get("usage-empty").hidden, false);
    assert.equal(view.get("connection-usage").hidden, true);
    assert.equal(view.text("official-total"), "—");
    assert.equal(view.text("compression-saved"), "—");
    assert.match(view.text("connection-badge"), /等待对话/);
    assert.doesNotMatch(view.text("traffic-state"), /20/);
  }
});

test("a new conversation immediately replaces every old total and request row", () => {
  const view = renderer();
  view.render({ tokens: usage() });
  view.render({ usage_scope: { started: true, id: "conversation-b", requests: 1, active_requests: 1 },
    tokens: { processing: true, local: { requests: 0 }, recent_requests: [] } });
  assert.equal(view.get("usage-data").hidden, false);
  assert.equal(view.text("official-total"), "—");
  assert.equal(view.text("compression-saved"), "—");
  assert.match(view.text("compression-summary"), /正在处理请求/);
  assert.equal(view.rows("request-rows").length, 1);
  assert.doesNotMatch(JSON.stringify(view.rows("request-rows")), /r1|r2/);
  const tokens = usage();
  tokens.local = { requests: 1, compressed_requests: 1, before: 100, after: 80, saved: 20, savings_percent: 20 };
  tokens.official = { total_tokens: 85, input_tokens: 80, output_tokens: 5, measured_requests: 1 };
  view.render({ usage_scope: { started: true, id: "conversation-b", requests: 1, active_requests: 0 }, tokens });
  assert.equal(view.text("compression-saved"), "20");
  assert.equal(view.text("official-total"), "85");
});

test("compression estimates are available before official usage arrives", () => {
  const view = renderer();
  view.render({ tokens: { local: usage().local, processing: true } });
  assert.equal(view.text("compression-saved"), "6,000");
  assert.equal(view.text("official-total"), "—");
  assert.match(view.text("compression-summary"), /正在处理新请求/);
});
