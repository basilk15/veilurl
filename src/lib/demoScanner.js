export const seedUrls = [
  "https://example-login-secure.com",
  "https://secure-bank-update.net",
  "https://github.com",
  "https://vercel.com",
  "https://free-games-download.xyz",
  "https://openai.com",
  "https://invoice-pay-secure.org",
  "https://netflix.com",
  "https://bit.ly/4k3Jm9",
  "https://crypto-airdrop-bonus.info",
];

const suspiciousWords = [
  "login",
  "verify",
  "secure",
  "account",
  "wallet",
  "free",
  "bonus",
  "reset",
  "bank",
  "invoice",
  "airdrop",
];

const unusualTlds = ["xyz", "info", "top", "click", "support", "zip", "work"];

export function hashString(value) {
  return [...value].reduce((hash, char) => (hash * 31 + char.charCodeAt(0)) >>> 0, 7);
}

export function normalizeUrl(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export function domainFromUrl(value) {
  try {
    return new URL(normalizeUrl(value)).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

export function riskLevel(score) {
  if (score >= 85) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export function statusFor(level) {
  if (level === "critical" || level === "high") return "fail";
  if (level === "medium") return "warn";
  return "pass";
}

export function levelLabel(level) {
  return {
    low: "Low",
    medium: "Medium",
    high: "High",
    critical: "Critical",
  }[level];
}

export function makeReport(rawUrl, index = 0) {
  const normalizedUrl = normalizeUrl(rawUrl);
  const domain = domainFromUrl(normalizedUrl) || "unknown.local";
  const hash = hashString(domain);
  const parts = domain.split(".");
  const tld = parts.at(-1) || "com";
  const hasHttps = normalizedUrl.startsWith("https://");
  const keywordHits = suspiciousWords.filter((word) => domain.includes(word));
  const tldRisk = unusualTlds.includes(tld) ? 10 : 0;
  const domainAge = 18 + (hash % 720);
  const headerMisses = hash % 5;
  const reputationHits = keywordHits.length > 1 ? 2 + (hash % 3) : hash % 11 === 0 ? 1 : 0;
  const redirectCount = keywordHits.length ? 2 + (hash % 2) : hash % 3;
  const risk =
    (hasHttps ? 0 : 20) +
    Math.min(keywordHits.length * 14, 35) +
    tldRisk +
    (domainAge < 240 ? 15 : 0) +
    (keywordHits.includes("login") && keywordHits.includes("secure") ? 18 : 0) +
    (headerMisses > 2 ? 10 : 0) +
    (reputationHits ? 25 : 0) +
    (redirectCount > 2 ? 10 : 0);
  const score = Math.min(100, Math.max(4, risk + (hash % 14)));
  const level = riskLevel(score);
  const scanId = `SNT-${hash.toString(16).slice(0, 8)}`;
  const responseMs = 120 + (hash % 840);
  const createdLabel = index === 0 ? "10:24 AM" : index < 4 ? "Yesterday" : `${10 + index} Jun 2026`;
  const isClean = level === "low";
  const createdAt = new Date(Date.now() - index * 1000 * 60 * 48).toISOString();

  return {
    id: scanId,
    url: normalizedUrl,
    inputUrl: rawUrl,
    normalizedUrl,
    domain,
    score,
    riskScore: score,
    level,
    riskLevel: level,
    status: statusFor(level),
    verdict: isClean ? "Looks safe" : level === "medium" ? "Review suggested" : "Review recommended",
    scannedAt: createdLabel,
    createdAt,
    updatedAt: createdAt,
    ip: `${20 + (hash % 180)}.${80 + (hash % 70)}.${12 + (hash % 180)}.${20 + (hash % 190)}`,
    server: hash % 2 ? "cloudflare" : "nginx",
    responseMs,
    registeredDays: domainAge,
    expiresDays: 90 + (hash % 360),
    keywordHits,
    redirectCount,
    reputationHits,
    headerMisses,
    tld,
    scoreBreakdown: {
      domain: Math.min(25, 6 + keywordHits.length * 8 + (domainAge < 120 ? 8 : 0)),
      security: Math.min(25, 25 - headerMisses * 4 - (hasHttps ? 0 : 8)),
      reputation: Math.min(25, reputationHits ? 18 + reputationHits * 2 : 4 + (hash % 8)),
      content: Math.min(25, 8 + keywordHits.length * 4 + redirectCount * 3),
    },
  };
}

export function makeSeedReports() {
  return seedUrls.map((url, index) => makeReport(url, index));
}
