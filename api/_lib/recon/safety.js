import dns from "node:dns/promises";
import net from "node:net";

const blockedHostnames = new Set(["localhost", "localhost.localdomain"]);

function inRange(value, start, end) {
  return value >= start && value <= end;
}

export function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const parts = ip.split(".").map(Number);
    const [a, b, c, d] = parts;
    const numeric = ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;

    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      inRange(numeric, 0xe0000000, 0xffffffff)
    );
  }

  if (net.isIP(ip) === 6) {
    const normalized = ip.toLowerCase();
    const mappedIpv4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1];

    if (mappedIpv4) {
      return isPrivateIp(mappedIpv4);
    }

    return (
      normalized === "::1" ||
      normalized === "::" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe80") ||
      normalized.startsWith("ff") ||
      normalized.startsWith("2001:db8")
    );
  }

  return true;
}

export async function assertSafePublicTarget(url) {
  const parsed = new URL(url);
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported");
  }

  if (blockedHostnames.has(hostname) || hostname.endsWith(".localhost")) {
    throw new Error("Localhost targets are not allowed");
  }

  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error("Private network targets are not allowed");
    }
    return { hostname, addresses: [hostname] };
  }

  const addresses = await dns.lookup(hostname, { all: true, verbatim: false });
  if (!addresses.length) {
    throw new Error("Target did not resolve");
  }

  const blocked = addresses.find((record) => isPrivateIp(record.address));
  if (blocked) {
    throw new Error("Target resolves to a private network address");
  }

  return {
    hostname,
    addresses: addresses.map((record) => record.address),
  };
}

export function withTimeout(promise, ms, label) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
  });

  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

export function safeError(error) {
  return error instanceof Error ? error.message : "Unknown recon error";
}
