"use strict";

// Rebuild the installer from an already packaged Windows directory. This keeps
// an installer retry from downloading Electron or rebuilding Python again.
const fs = require("node:fs");
const path = require("node:path");
const { createWindowsInstaller } = require("electron-winstaller");
const config = require("../forge.config.cjs");

async function main() {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) throw new Error("Usage: node scripts/make-windows-installer.cjs <packaged-app> <output>");
  const appDirectory = path.resolve(input);
  const outputDirectory = path.resolve(output);
  const exe = `${config.packagerConfig.executableName}.exe`;
  for (const required of [exe, "resources/app.asar", "resources/lingmou-backend/lingmou-backend.exe"]) {
    if (!fs.existsSync(path.join(appDirectory, required))) throw new Error(`Incomplete Windows package: ${required}`);
  }
  if (process.platform !== "win32") {
    const vendor = path.resolve(path.dirname(require.resolve("electron-winstaller")), "../vendor");
    for (const extension of ["exe", "dll"]) {
      const legacy = path.join(vendor, `7z.${extension}`);
      if (!fs.existsSync(legacy)) fs.copyFileSync(path.join(vendor, `7z-x64.${extension}`), legacy);
    }
  }
  const maker = config.makers.find((entry) => entry.name === "@electron-forge/maker-squirrel");
  await createWindowsInstaller({ ...maker.config, appDirectory, outputDirectory, exe });
  console.log(`Windows installer created: ${path.join(outputDirectory, maker.config.setupExe)}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
