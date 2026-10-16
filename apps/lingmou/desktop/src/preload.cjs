const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("lingmouDesktop", {
  getState: () => ipcRenderer.invoke("launcher:get-state"),
  openCompression: () => ipcRenderer.invoke("launcher:open-compression"),
  chooseAndStart: () => ipcRenderer.invoke("launcher:choose-and-start"),
  startLast: () => ipcRenderer.invoke("launcher:start-last"),
  connectExisting: () => ipcRenderer.invoke("launcher:connect-existing"),
  connectService: (serviceUrl, fingerprint) => ipcRenderer.invoke(
    "launcher:connect-service",
    serviceUrl,
    fingerprint,
  ),
  quit: () => ipcRenderer.send("launcher:quit"),
  onStatus: (callback) => {
    const listener = (_event, state) => callback(state);
    ipcRenderer.on("launcher:status", listener);
    return () => ipcRenderer.removeListener("launcher:status", listener);
  },
});
