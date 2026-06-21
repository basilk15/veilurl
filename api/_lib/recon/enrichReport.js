import { riskLevel, statusFor } from "../../../src/lib/demoScanner.js";
import { makeSummary } from "../../../src/lib/localNarrator.js";

function present(value) {
  return Boolean(value && value !== "Not available");
}

function headerPresent(headers, name) {
  return Boolean(headers?.checks?.find((check) => check.name === name && check.present));
}

function clampScore(value) {
  return Math.min(100, Math.max(0, Math.round(value)));
}

export function enrichReportWithRecon(report, recon) {
  const dns = recon?.dns?.data;
  const http = recon?.http?.data;
  const tls = recon?.tls?.data;
  const rdap = recon?.rdap?.data;
  const securityTxt = recon?.securityTxt?.data;
  const robotsTxt = recon?.robotsTxt?.data;

  const next = {
    ...report,
    recon,
    ip: dns?.a?.[0] || recon?.target?.addresses?.[0] || report.ip,
    server: http?.server || report.server,
    redirectCount: typeof http?.hopCount === "number" ? http.hopCount : report.redirectCount,
    headerMisses:
      typeof http?.headers?.missing?.length === "number" ? http.headers.missing.length : report.headerMisses,
    registeredDays: typeof rdap?.registeredDays === "number" ? rdap.registeredDays : report.registeredDays,
    expiresDays:
      typeof rdap?.expiresDays === "number"
        ? rdap.expiresDays
        : typeof tls?.daysRemaining === "number"
          ? tls.daysRemaining
          : report.expiresDays,
  };

  let risk = 0;
  if (!next.url.startsWith("https://")) risk += 20;
  risk += Math.min(next.keywordHits.length * 14, 35);
  if (next.registeredDays < 120) risk += 15;
  if (next.keywordHits.includes("login") && next.keywordHits.includes("secure")) risk += 18;
  if (next.tld && ["xyz", "info", "top", "click", "support", "zip", "work"].includes(next.tld)) risk += 10;

  if (http?.crossDomain) risk += 12;
  if ((http?.hopCount || 0) > 2) risk += 8;
  if (http?.finalStatus >= 400 || http?.finalStatus === 0) risk += 12;
  if (!headerPresent(http?.headers, "strict-transport-security")) risk += next.url.startsWith("https://") ? 8 : 0;
  if (!headerPresent(http?.headers, "content-security-policy")) risk += 6;
  if (!headerPresent(http?.headers, "x-frame-options")) risk += 4;
  if (!headerPresent(http?.headers, "x-content-type-options")) risk += 4;
  if (tls?.expired) risk += 35;
  if (tls?.expiringSoon) risk += 12;
  if (tls?.available === false && next.url.startsWith("https://")) risk += 20;
  if (dns?.mailSecurity?.mxPresent && !dns.mailSecurity.spfPresent) risk += 5;
  if (dns?.mailSecurity?.mxPresent && !dns.mailSecurity.dmarcPresent) risk += 8;
  if (next.reputationHits) risk += 20;

  const posturePenalty =
    next.headerMisses * 8 +
    (next.url.startsWith("https://") ? 0 : 12) +
    (tls?.expired ? 35 : 0) +
    (tls?.expiringSoon ? 12 : 0) +
    (tls?.available === false && next.url.startsWith("https://") ? 20 : 0) +
    (dns?.mailSecurity?.mxPresent && !dns.mailSecurity.spfPresent ? 6 : 0) +
    (dns?.mailSecurity?.mxPresent && !dns.mailSecurity.dmarcPresent ? 8 : 0) +
    (securityTxt?.found === false ? 3 : 0);

  next.score = clampScore(Math.max(4, risk));
  next.riskScore = next.score;
  next.threatScore = next.score;
  next.postureScore = clampScore(100 - posturePenalty);
  next.level = riskLevel(next.score);
  next.riskLevel = next.level;
  next.status = statusFor(next.level);
  next.verdict =
    next.level === "low" ? "Looks safe" : next.level === "medium" ? "Review suggested" : "Review recommended";
  next.scoreBreakdown = {
    domain: clampScore(
      Math.min(25, 4 + next.keywordHits.length * 6 + (next.registeredDays < 120 ? 8 : 0) + (rdap?.found ? 0 : 4)),
    ),
    security: clampScore(
      Math.max(
        0,
        25 -
          next.headerMisses * 3 -
          (tls?.expired ? 12 : 0) -
          (tls?.expiringSoon ? 5 : 0) -
          (next.url.startsWith("https://") ? 0 : 8),
      ),
    ),
    reputation: clampScore(
      Math.min(
        25,
        next.reputationHits
          ? 18 + next.reputationHits * 2
          : 3 + (securityTxt?.found ? 0 : 2) + (robotsTxt?.found ? 0 : 1),
      ),
    ),
    content: clampScore(
      Math.min(25, 5 + next.keywordHits.length * 4 + next.redirectCount * 3 + (http?.crossDomain ? 6 : 0)),
    ),
  };
  next.summary = makeSummary(next);

  if (!present(next.server) && http?.headers?.checks) {
    next.server = "Not disclosed";
  }

  return next;
}
