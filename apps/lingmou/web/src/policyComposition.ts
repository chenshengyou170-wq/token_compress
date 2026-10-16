export type Predicate = { atom: string } | { field: string; op: string; value: unknown } | { all: Predicate[] } | { any: Predicate[] } | { not: Predicate };
export type MetaPolicy = { id: string; name: string; category: string; description: string; predicate: Predicate; parameter: null | { kind: "strings" | "ports" | "methods"; placeholder: string } };
export type Clause = { id: string; metaId: string; input: string; exclude: boolean };

export function clausePredicate(meta: MetaPolicy, input: string): Predicate {
  if (!meta.parameter) return { atom: meta.id };
  const words = input.split(/[,，\n]/).map((s) => s.trim()).filter(Boolean);
  if (!words.length) throw new Error(`请填写“${meta.name}”的匹配值。`);
  if (words.length > 512) throw new Error("每个条件最多填写 512 项。");
  let values: (string | number)[] = words;
  if (meta.parameter.kind === "ports") {
    if (words.some((v) => !/^\d+$/.test(v) || Number(v) < 1 || Number(v) > 65535)) throw new Error("端口应为 1 至 65535 的整数。");
    values = words.map(Number);
  } else if (meta.parameter.kind === "methods") values = words.map((v) => v.toUpperCase());
  const node = structuredClone(meta.predicate);
  const leaf = "not" in node ? node.not : node;
  if (!("field" in leaf)) throw new Error("元策略格式无效，请重新载入配置。");
  leaf.value = [...new Set(values)];
  return node;
}

export function composePolicy(catalog: MetaPolicy[], clauses: Clause[], join: "all" | "any"): Predicate {
  const positive: Predicate[] = [], exceptions: Predicate[] = [];
  if (clauses.length > 32) throw new Error("一组规则最多组合 32 个条件。");
  for (const clause of clauses) {
    const meta = catalog.find((item) => item.id === clause.metaId);
    if (!meta) throw new Error("请选择有效的元策略。");
    (clause.exclude ? exceptions : positive).push(clausePredicate(meta, clause.input));
  }
  if (!positive.length) throw new Error("至少添加一个触发条件，排除条件不能单独构成规则。");
  const trigger: Predicate = { [join]: positive } as Predicate;
  return exceptions.length ? { all: [trigger, { not: { any: exceptions } }] } : trigger;
}
