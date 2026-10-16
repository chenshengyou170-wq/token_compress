import { describe, expect, it } from "vitest";
import { clausePredicate, composePolicy, type MetaPolicy } from "./policyComposition";
const items: MetaPolicy[] = [
  { id: "meta.network.upload", name: "上传", category: "网络", description: "", parameter: null, predicate: { field: "network.upload", op: "eq", value: true } },
  { id: "meta.network.outside_domains", name: "名单外", category: "网络", description: "", parameter: { kind: "strings", placeholder: "" }, predicate: { not: { field: "network.hosts", op: "domains_subset", value: [] } } },
  { id: "meta.network.ports", name: "端口", category: "网络", description: "", parameter: { kind: "ports", placeholder: "" }, predicate: { field: "network.ports", op: "intersects", value: [] } },
];
describe("policy composition", () => {
  it("preserves upload AND every destination allowlist semantics", () => {
    const when = composePolicy(items, [
      { id: "a", metaId: items[0].id, input: "", exclude: false },
      { id: "b", metaId: items[1].id, input: "example.com, *.example.com", exclude: false },
    ], "all");
    expect(when).toEqual({ all: [{ atom: items[0].id }, { not: { field: "network.hosts", op: "domains_subset", value: ["example.com", "*.example.com"] } }] });
    expect(items[1].predicate).toEqual({ not: { field: "network.hosts", op: "domains_subset", value: [] } });
  });
  it("keeps exclusions outside the any group and parses numeric ports", () => {
    expect(composePolicy(items, [
      { id: "a", metaId: items[0].id, input: "", exclude: false },
      { id: "b", metaId: items[2].id, input: "443，8443", exclude: true },
    ], "any")).toEqual({ all: [{ any: [{ atom: items[0].id }] }, { not: { any: [{ field: "network.ports", op: "intersects", value: [443, 8443] }] } }] });
  });
  it("rejects empty, malformed and exclusion-only conditions", () => {
    expect(() => clausePredicate(items[1], "")).toThrow("匹配值");
    for (const value of ["443x", "0", "65536", "22.5"]) expect(() => clausePredicate(items[2], value)).toThrow("端口");
    expect(() => composePolicy(items, [{ id: "a", metaId: items[0].id, input: "", exclude: true }], "all")).toThrow("触发条件");
  });
});
