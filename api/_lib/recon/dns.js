import dns from "node:dns/promises";
import { withTimeout } from "./safety.js";

async function resolveOrEmpty(fn) {
  try {
    return await withTimeout(fn(), 3500, "DNS lookup");
  } catch {
    return [];
  }
}

function flattenTxt(records) {
  return records.map((entry) => entry.join(""));
}

export async function collectDnsRecon(domain) {
  const [a, aaaa, mx, ns, txt, dmarcTxt] = await Promise.all([
    resolveOrEmpty(() => dns.resolve4(domain)),
    resolveOrEmpty(() => dns.resolve6(domain)),
    resolveOrEmpty(() => dns.resolveMx(domain)),
    resolveOrEmpty(() => dns.resolveNs(domain)),
    resolveOrEmpty(() => dns.resolveTxt(domain)),
    resolveOrEmpty(() => dns.resolveTxt(`_dmarc.${domain}`)),
  ]);

  const txtFlat = flattenTxt(txt);
  const dmarcFlat = flattenTxt(dmarcTxt);
  const spf = txtFlat.find((record) => record.toLowerCase().startsWith("v=spf1")) || "";
  const dmarc = dmarcFlat.find((record) => record.toLowerCase().startsWith("v=dmarc1")) || "";

  return {
    a,
    aaaa,
    mx: mx.sort((left, right) => left.priority - right.priority),
    ns,
    txt: txtFlat,
    spf: {
      present: Boolean(spf),
      record: spf,
    },
    dmarc: {
      present: Boolean(dmarc),
      record: dmarc,
    },
    mailSecurity: {
      mxPresent: mx.length > 0,
      spfPresent: Boolean(spf),
      dmarcPresent: Boolean(dmarc),
    },
  };
}
