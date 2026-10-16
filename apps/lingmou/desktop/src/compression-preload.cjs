const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("lingmouCompression", {
  command: (method, params) => ipcRenderer.invoke("compression:command", method, params),
  environment: () => ipcRenderer.invoke("compression:environment"),
  setAutoStart: (enabled) => ipcRenderer.invoke("compression:auto-start", enabled),
  chooseConfig: () => ipcRenderer.invoke("compression:choose-config"),
  showFiles: () => ipcRenderer.invoke("compression:show-files"),
  securityHome: () => ipcRenderer.send("compression:security-home"),
  onState: (callback) => {
    const listener = (_event, state) => callback(state);
    ipcRenderer.on("compression:state", listener);
    return () => ipcRenderer.removeListener("compression:state", listener);
  },
});
