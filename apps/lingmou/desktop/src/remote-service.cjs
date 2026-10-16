const crypto = require("node:crypto");
const https = require("node:https");
const net = require("node:net");
const tls = require("node:tls");

const ACCESS_COOKIE = "lingmou_access";
const MAX_SERVICE_URL_LENGTH = 2_048;
const MAX_STATE_BYTES = 256 * 1024;

class RemoteServiceError extends Error {
  constructor(message) {
    super(message);
    this.name = "RemoteServiceError";
  }
}

function normalizedFingerprint(value) {
  const normalized = String(value || "")
    .trim()
    .replace(/^SHA256(?:\s+Fingerprint)?\s*=\s*/i, "")
    .replaceAll(":", "")
    .replace(/\s+/g, "")
    .toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(normalized)) {
    throw new RemoteServiceError("证书指纹必须是 64 位 SHA-256 十六进制值");
  }
  return normalized;
}

function normalizedHostname(value) {
  const hostname = String(value || "").toLowerCase();
  if (hostname.startsWith("[") && hostname.endsWith("]")) return hostname.slice(1, -1);
  return hostname;
}

function isPrivateHostname(value) {
  const hostname = normalizedHostname(value);
  if (hostname === "localhost") return true;
  const family = net.isIP(hostname);
  if (family === 4) {
    const [first, second] = hostname.split(".").map(Number);
    return first === 10
      || first === 127
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || (first === 169 && second === 254);
  }
  if (family === 6) {
    return hostname === "::1"
      || hostname.startsWith("fc")
      || hostname.startsWith("fd")
      || /^fe[89ab]/.test(hostname);
  }
  return false;
}

function parseRemoteServiceUrl(value) {
  if (typeof value !== "string" || !value.trim() || value.length > MAX_SERVICE_URL_LENGTH) {
    throw new RemoteServiceError("请输入完整的灵眸服务登录链接");
  }
  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new RemoteServiceError("灵眸服务链接格式无效");
  }
  if (parsed.protocol !== "https:") {
    throw new RemoteServiceError("远程灵眸服务必须使用 HTTPS");
  }
  if (parsed.username || parsed.password) {
    throw new RemoteServiceError("灵眸服务链接不能包含用户名或密码");
  }
  if (!isPrivateHostname(parsed.hostname)) {
    throw new RemoteServiceError("灵眸 App 只连接 localhost 或私网 IP");
  }
  if (!parsed.port) {
    throw new RemoteServiceError("灵眸服务链接必须包含明确端口");
  }
  if (parsed.pathname !== "/" || parsed.hash) {
    throw new RemoteServiceError("灵眸服务链接只允许根路径，且不能包含片段");
  }
  const tokenValues = parsed.searchParams.getAll("access_token");
  const queryKeys = [...parsed.searchParams.keys()];
  if (
    queryKeys.length !== 1
    || queryKeys[0] !== "access_token"
    || tokenValues.length !== 1
    || !/^[A-Za-z0-9._~-]{16,512}$/.test(tokenValues[0])
  ) {
    throw new RemoteServiceError("灵眸服务链接必须包含且仅包含一个有效 access_token");
  }
  return Object.freeze({
    hostname: normalizedHostname(parsed.hostname),
    port: Number(parsed.port),
    origin: parsed.origin,
    token: tokenValues[0],
  });
}

function fingerprintForCertificate(certificate) {
  if (!certificate?.raw) throw new RemoteServiceError("服务没有提供可校验的 TLS 证书");
  return crypto.createHash("sha256").update(certificate.raw).digest("hex").toUpperCase();
}

function certificatePem(certificate) {
  const encoded = certificate.raw.toString("base64").match(/.{1,64}/g)?.join("\n");
  if (!encoded) throw new RemoteServiceError("无法读取灵眸服务 TLS 证书");
  return `-----BEGIN CERTIFICATE-----\n${encoded}\n-----END CERTIFICATE-----\n`;
}

function validateCertificateIdentity(connection, certificate, expectedFingerprint) {
  const actualFingerprint = fingerprintForCertificate(certificate);
  if (actualFingerprint !== expectedFingerprint) {
    throw new RemoteServiceError("服务证书指纹不匹配；为保护访问令牌，连接已停止");
  }
  const identityError = tls.checkServerIdentity(connection.hostname, certificate);
  if (identityError) {
    throw new RemoteServiceError("服务证书与目标主机不匹配");
  }
  const validFrom = Date.parse(certificate.valid_from);
  const validTo = Date.parse(certificate.valid_to);
  const now = Date.now();
  if (!Number.isFinite(validFrom) || !Number.isFinite(validTo) || now < validFrom || now > validTo) {
    throw new RemoteServiceError("服务 TLS 证书尚未生效或已经过期");
  }
  return actualFingerprint;
}

function readPinnedCertificate(connection, expectedFingerprint, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.destroy();
      if (error) reject(error); else resolve(value);
    };
    const socket = tls.connect({
      host: connection.hostname,
      port: connection.port,
      rejectUnauthorized: false,
      ...(net.isIP(connection.hostname) ? {} : { servername: connection.hostname }),
    });
    const timeout = setTimeout(
      () => finish(new RemoteServiceError("连接灵眸服务超时，请检查地址与网络")),
      timeoutMs,
    );
    socket.once("secureConnect", () => {
      try {
        const certificate = socket.getPeerCertificate(true);
        validateCertificateIdentity(connection, certificate, expectedFingerprint);
        finish(null, certificate);
      } catch (error) {
        finish(error);
      }
    });
    socket.once("error", () => finish(new RemoteServiceError("无法建立灵眸服务 TLS 连接")));
  });
}

function requestState(connection, certificate, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let body = "";
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve(value);
    };
    const request = https.request({
      method: "GET",
      hostname: connection.hostname,
      port: connection.port,
      path: "/api/v1/state",
      ca: certificatePem(certificate),
      rejectUnauthorized: true,
      ...(net.isIP(connection.hostname) ? {} : { servername: connection.hostname }),
      headers: {
        Accept: "application/json",
        Cookie: `${ACCESS_COOKIE}=${connection.token}`,
      },
      timeout: timeoutMs,
    }, (response) => {
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
        if (Buffer.byteLength(body, "utf8") > MAX_STATE_BYTES) {
          request.destroy(new RemoteServiceError("灵眸服务状态响应过大"));
        }
      });
      response.on("end", () => {
        if (response.statusCode === 401) {
          finish(new RemoteServiceError("访问令牌无效或已经过期，请复制最新完整链接"));
          return;
        }
        if (response.statusCode !== 200) {
          finish(new RemoteServiceError(`灵眸服务状态检查失败（HTTP ${response.statusCode || "未知"}）`));
          return;
        }
        let state;
        try {
          state = JSON.parse(body);
        } catch {
          finish(new RemoteServiceError("服务响应不是有效的灵眸状态数据"));
          return;
        }
        if (
          !state
          || state.connected !== true
          || typeof state.workspace !== "string"
          || !["observe", "enforce"].includes(state.security_mode)
        ) {
          finish(new RemoteServiceError("服务可达，但当前 Agent 监控尚未就绪"));
          return;
        }
        finish(null, state);
      });
    });
    request.once("timeout", () => request.destroy(new RemoteServiceError("读取灵眸服务状态超时")));
    request.once("error", (error) => {
      finish(error instanceof RemoteServiceError
        ? error
        : new RemoteServiceError("无法读取灵眸服务状态"));
    });
    request.end();
  });
}

async function probeRemoteService(serviceUrl, fingerprint, timeoutMs = 8_000) {
  const connection = parseRemoteServiceUrl(serviceUrl);
  const expectedFingerprint = normalizedFingerprint(fingerprint);
  const certificate = await readPinnedCertificate(connection, expectedFingerprint, timeoutMs);
  const state = await requestState(connection, certificate, timeoutMs);
  return {
    origin: connection.origin,
    hostname: connection.hostname,
    port: connection.port,
    token: connection.token,
    fingerprint: expectedFingerprint,
    state: {
      workspace: state.workspace,
      run_dir: typeof state.run_dir === "string" ? state.run_dir : "",
      security_mode: state.security_mode,
      agent_backend: typeof state.agent_backend === "string" ? state.agent_backend : "codex",
    },
  };
}

module.exports = {
  ACCESS_COOKIE,
  RemoteServiceError,
  isPrivateHostname,
  normalizedFingerprint,
  parseRemoteServiceUrl,
  probeRemoteService,
};
