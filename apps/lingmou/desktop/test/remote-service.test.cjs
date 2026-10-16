const assert = require("node:assert/strict");
const test = require("node:test");

const {
  RemoteServiceError,
  isPrivateHostname,
  normalizedFingerprint,
  parseRemoteServiceUrl,
} = require("../src/remote-service.cjs");

const TOKEN = "A_safe-token_1234567890";

test("remote service parser accepts one token-bearing private HTTPS origin", () => {
  const parsed = parseRemoteServiceUrl(
    `https://192.168.31.108:8766/?access_token=${TOKEN}`,
  );
  assert.equal(parsed.origin, "https://192.168.31.108:8766");
  assert.equal(parsed.hostname, "192.168.31.108");
  assert.equal(parsed.port, 8766);
  assert.equal(parsed.token, TOKEN);
});

test("remote service parser rejects public, ambiguous, and token-leaking URLs", () => {
  const invalid = [
    `http://192.168.31.108:8766/?access_token=${TOKEN}`,
    `https://8.8.8.8:8766/?access_token=${TOKEN}`,
    `https://192.168.31.108/?access_token=${TOKEN}`,
    "https://192.168.31.108:8766/",
    `https://192.168.31.108:8766/path?access_token=${TOKEN}`,
    `https://192.168.31.108:8766/?access_token=${TOKEN}&debug=1`,
    `https://192.168.31.108:8766/?access_token=${TOKEN}&access_token=${TOKEN}`,
    `https://user:password@192.168.31.108:8766/?access_token=${TOKEN}`,
    `https://192.168.31.108:8766/?access_token=${TOKEN}#/overview`,
  ];
  for (const value of invalid) {
    assert.throws(() => parseRemoteServiceUrl(value), RemoteServiceError, value);
  }
});

test("remote connection scope accepts only loopback and private addresses", () => {
  for (const value of ["localhost", "127.0.0.1", "10.2.3.4", "172.20.1.2", "192.168.1.7", "::1", "fd00::1"]) {
    assert.equal(isPrivateHostname(value), true, value);
  }
  for (const value of ["example.com", "8.8.8.8", "172.32.1.2", "1.1.1.1", "2001:4860:4860::8888"]) {
    assert.equal(isPrivateHostname(value), false, value);
  }
});

test("certificate fingerprint normalization accepts common SHA-256 display forms", () => {
  const compact = "0D5945DBF1D201585000365F5AD28B80AB1D36C6BD7C4C8C550A6B91668BB04A";
  const colon = compact.match(/.{2}/g).join(":");
  assert.equal(normalizedFingerprint(colon), compact);
  assert.equal(normalizedFingerprint(`SHA256 Fingerprint=${colon}`), compact);
  assert.throws(() => normalizedFingerprint("not-a-fingerprint"), RemoteServiceError);
});
