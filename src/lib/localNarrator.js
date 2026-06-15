export function makeSummary(report) {
  const hasRecon = Boolean(report.recon);

  if (report.level === "low") {
    const notes = [
      report.headerMisses > 2 && "some security headers are missing",
      report.redirectCount > 2 && "redirect chain is longer than expected",
      report.recon?.securityTxt?.data?.found === false && "security.txt was not published",
    ].filter(Boolean);

    if (hasRecon && notes.length) {
      return `The URL is low risk overall, but passive recon found ${notes.join(", ")}. It does not show strong phishing indicators, so normal monitoring is reasonable.`;
    }

    return hasRecon
      ? "The URL shows a clean passive recon posture. The domain has stable signals, low reputation noise, and no major header or redirect concerns. Continue normal monitoring."
      : "The URL shows a clean sample posture. The domain has stable signals, low reputation noise, and no major modeled header or redirect concerns. Continue normal monitoring.";
  }

  const flags = [
    report.registeredDays < 120 && "new domain age",
    report.keywordHits.length > 0 && "suspicious wording",
    report.reputationHits > 0 && "reputation flags",
    report.headerMisses > 2 && "weak header posture",
    report.redirectCount > 2 && "redirect complexity",
  ].filter(Boolean);

  return `This URL shows ${flags.length ? flags.join(", ") : "multiple risk indicators"}. The overall pattern suggests users should review the destination before trusting forms, downloads, or account prompts.`;
}
