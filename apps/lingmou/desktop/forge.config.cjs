const fs = require("node:fs");
const path = require("node:path");

const backendBundle = path.join(__dirname, "dist", "backend", "lingmou-backend");
const extraResource = fs.existsSync(backendBundle) ? [backendBundle] : [];
const windowsSigning = process.env.WINDOWS_CERTIFICATE_FILE ? {
  certificateFile: process.env.WINDOWS_CERTIFICATE_FILE,
  certificatePassword: process.env.WINDOWS_CERTIFICATE_PASSWORD,
} : {};

module.exports = {
  packagerConfig: {
    asar: true,
    executableName: "lingmou-agent-security",
    icon: path.join(__dirname, "assets", "icon"),
    extraResource,
    electronLanguages: ["zh-CN", "en-US"],
    ignore: [
      /^\/(?:build|dist|scripts|test)(?:\/|$)/,
      /^\/(?:backend_entry\.py|forge\.config\.cjs|lingmou-backend\.spec|package-lock\.json)$/,
    ],
  },
  rebuildConfig: {},
  makers: [
    {
      name: "@electron-forge/maker-deb",
      platforms: ["linux"],
      config: {
        options: {
          name: "lingmou-agent-security",
          productName: "灵眸 Agent 安全中心",
          maintainer: "Lingmou",
          categories: ["Development", "Security"],
          icon: path.join(__dirname, "assets", "icon.png"),
        },
      },
    },
    {
      name: "@electron-forge/maker-squirrel",
      platforms: ["win32"],
      config: {
        name: "Lingmou",
        authors: "Lingmou",
        description: "Lingmou local Token compression companion for Codex.",
        setupExe: "Lingmou-Setup.exe",
        noMsi: true,
        setupIcon: path.join(__dirname, "assets", "icon.ico"),
        ...windowsSigning,
      },
    },
    {
      name: "@electron-forge/maker-zip",
      platforms: ["linux", "win32"],
    },
  ],
};
