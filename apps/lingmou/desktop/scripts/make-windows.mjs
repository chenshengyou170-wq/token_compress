import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  throw new Error("Windows 后端必须在 Windows 构建。请在 Windows 11 x64 运行 npm run make:windows。");
}
if (process.arch !== "x64") throw new Error("当前安装包目标为 Windows x64，请使用 x64 Node.js 和 Python。");
const desktop = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const result = spawnSync(process.execPath, [process.env.npm_execpath, "run", "make", "--", "--platform=win32", "--arch=x64"], {
  cwd: desktop, stdio: "inherit", windowsHide: true,
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
