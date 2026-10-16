import { describe, expect, it } from "vitest";
import {
  aggregateDensityBuckets,
  collectionPresentation,
  densityBucketLimitForWidth,
  formatSyscallBytes,
  formatSyscallCount,
  indexHealthPresentation,
  isBehaviorEvent,
  syscallMatchesFilters,
  syscallTarget,
  type ExplorerFilters,
} from "./components/SyscallExplorer";
import type { SyscallEvent } from "./types";
import type { SyscallDensityBucket, SyscallStatus } from "./types";

const baseFilters: ExplorerFilters = {
  preset: "all",
  query: "",
  syscall: "",
  category: "",
  success: "all",
  pid: null,
  fromNs: null,
  toNs: null,
};

const event: SyscallEvent = {
  seq: 42,
  wall_time_ns: 1_700_000_000_000_000_000,
  pid: 120,
  tid: 121,
  ppid: 100,
  comm: "node",
  syscall: "connect",
  category: "network",
  access: "connect",
  endpoint_text: "127.0.0.1:8765",
  result: -1,
  errno: "ECONNREFUSED",
  success: false,
  agent_item: {
    item_id: "item-7",
    confidence_tier: "fact",
    basis: "exact_pid_and_lifecycle",
  },
};

describe("system call presentation contract", () => {
  it("formats compact counts and sizes without exposing payloads", () => {
    expect(formatSyscallCount(200_000)).toBe("200,000");
    expect(formatSyscallBytes(1_536)).toBe("1.5 KB");
    expect(syscallTarget(event)).toBe("127.0.0.1:8765");
    expect(event).not.toHaveProperty("payload");
  });

  it("filters by process, result, syscall, time, and agent item", () => {
    expect(syscallMatchesFilters(event, {
      ...baseFilters,
      pid: 120,
      success: "failed",
      syscall: "conn",
      fromNs: event.wall_time_ns - 1,
      toNs: event.wall_time_ns + 1,
    }, "item-7")).toBe(true);
    expect(syscallMatchesFilters(event, { ...baseFilters, pid: 999 })).toBe(false);
    expect(syscallMatchesFilters(event, baseFilters, "another-item")).toBe(false);
  });

  it("keeps the behavior view semantic and deterministic", () => {
    expect(syscallMatchesFilters(event, { ...baseFilters, preset: "behavior" })).toBe(true);
    const routineExternalRead: SyscallEvent = {
      ...event,
      seq: 43,
      syscall: "read",
      category: "file",
      access: "read",
      endpoint_text: null,
      path: "/usr/lib/libc.so",
      path_scope: "external",
      success: true,
      errno: null,
    };
    expect(isBehaviorEvent(routineExternalRead)).toBe(false);
    expect(syscallMatchesFilters(routineExternalRead, { ...baseFilters, preset: "behavior" })).toBe(false);
    expect(isBehaviorEvent({ ...routineExternalRead, path: "src/report.ts", path_scope: "workspace" })).toBe(true);
    expect(isBehaviorEvent({
      ...routineExternalRead,
      syscall: "execve",
      category: "process",
      access: "execute",
      success: false,
      errno: "ENOENT",
    })).toBe(false);
  });

  it("aggregates density into reliable mobile hit targets", () => {
    const buckets: SyscallDensityBucket[] = Array.from({ length: 96 }, (_, index) => ({
      index,
      from_ns: index * 10,
      to_ns: index * 10 + 9,
      total: 1,
      failed: index % 3 === 0 ? 1 : 0,
      network: index % 2,
      writes: 0,
    }));
    const mobile = aggregateDensityBuckets(buckets, densityBucketLimitForWidth(390));
    expect(mobile).toHaveLength(8);
    expect(mobile[0]).toMatchObject({ from_ns: 0, to_ns: 119, total: 12, failed: 4, network: 6 });
    expect(densityBucketLimitForWidth(1440)).toBe(48);
  });

  it("never reports an unknown or failed status as collection disabled", () => {
    expect(collectionPresentation(null, false, null).title).toBe("正在读取系统调用状态");
    expect(collectionPresentation(null, false, "offline").title).toBe("采集状态更新失败");
    expect(collectionPresentation(null, false, "offline").detail).toContain("不会把未知状态写成未启用");
  });

  it("makes a partial raw line explicit without treating it as data loss", () => {
    const status = {
      index: { partial_line: true, parse_errors: 0, lag_events: 0 },
      collection: { known_loss: false },
    } as SyscallStatus;
    expect(indexHealthPresentation(status)).toEqual({
      value: "等待完整行",
      detail: "原始末行仍在写入，暂不索引",
      warning: false,
    });
  });
});
