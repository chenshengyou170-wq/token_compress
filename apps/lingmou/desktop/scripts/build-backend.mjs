import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const projectRoot = resolve(desktopRoot, "..");
const python = process.platform === "win32"
  ? join(projectRoot, ".venv", "Scripts", "python.exe")
  : join(projectRoot, ".venv", "bin", "python");

if (!existsSync(python)) {
  throw new Error(`Python environment not found: ${python}`);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

// npm.cmd cannot be spawned directly without a shell on Windows. npm scripts
// provide the JS entry point, so keep paths/arguments out of shell parsing.
const npmCli = process.env.npm_execpath;
if (!npmCli || !existsSync(npmCli)) {
  throw new Error("Run this script through npm run build:backend.");
}
run(process.execPath, [npmCli, "run", "build"], join(projectRoot, "web"));
run(python, [join(desktopRoot, "scripts", "prepare-assets.py")], projectRoot);
run(
  python,
  [
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--distpath", join(desktopRoot, "dist", "backend"),
    "--workpath", join(desktopRoot, "build", "pyinstaller"),
    join(desktopRoot, "lingmou-backend.spec"),
  ],
  projectRoot,
);
