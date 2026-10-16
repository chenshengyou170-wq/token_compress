const { app, BrowserWindow } = require("electron");
const fs = require("node:fs");

const target = process.argv[2];
const output = process.argv[3];

if (!target || !output) {
  process.stderr.write("usage: electron capture-page.cjs URL OUTPUT.png\n");
  process.exit(2);
}

app.enableSandbox();
app.whenReady().then(async () => {
  const window = new BrowserWindow({
    width: 1440,
    height: 900,
    show: false,
    backgroundColor: "#f2f5f7",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
    },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  await window.loadURL(target);
  await window.webContents.executeJavaScript("document.fonts.ready");
  await new Promise((resolve) => setTimeout(resolve, 1_200));
  const image = await window.webContents.capturePage();
  fs.writeFileSync(output, image.toPNG());
  window.destroy();
  app.quit();
});
