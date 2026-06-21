import { collectDnsRecon } from "./dns.js";
import { collectHttpRecon } from "./http.js";
import { collectRdapRecon } from "./rdap.js";
import { assertSafePublicTarget, safeError } from "./safety.js";
import { collectTlsRecon } from "./tls.js";
import { collectRobotsTxt, collectSecurityTxt } from "./wellKnown.js";

async function capture(label, fn) {
  try {
    return {
      ok: true,
      data: await fn(),
    };
  } catch (error) {
    return {
      ok: false,
      error: safeError(error),
      data: null,
      label,
    };
  }
}

export async function runPassiveRecon(inputUrl) {
  const parsed = new URL(inputUrl);
  const safeTarget = await assertSafePublicTarget(inputUrl);
  const origin = `${parsed.protocol}//${parsed.host}`;

  const [dns, rdap, http, tls, securityTxt, robotsTxt] = await Promise.all([
    capture("dns", () => collectDnsRecon(safeTarget.hostname)),
    capture("rdap", () => collectRdapRecon(safeTarget.hostname)),
    capture("http", () => collectHttpRecon(inputUrl)),
    capture("tls", () =>
      parsed.protocol === "https:"
        ? collectTlsRecon(safeTarget.hostname)
        : Promise.resolve({ available: false, error: "HTTPS not used" }),
    ),
    capture("securityTxt", () => collectSecurityTxt(origin)),
    capture("robotsTxt", () => collectRobotsTxt(origin)),
  ]);

  return {
    target: {
      inputUrl,
      hostname: safeTarget.hostname,
      addresses: safeTarget.addresses,
      origin,
    },
    dns,
    rdap,
    http,
    tls,
    securityTxt,
    robotsTxt,
    collectedAt: new Date().toISOString(),
  };
}
