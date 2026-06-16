import {
  Archive,
  Bell,
  BookOpen,
  Check,
  ChevronRight,
  CircleDot,
  Clock3,
  Copy,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileText,
  Filter,
  Globe2,
  History,
  Info,
  KeyRound,
  Link2,
  LockKeyhole,
  Menu,
  Plus,
  RefreshCw,
  RotateCcw,
  ScanSearch,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { deleteReportById, fallbackReports, fallbackScan, fetchReports, scanUrl } from "./lib/apiClient.js";
import { makeSeedReports, normalizeUrl, levelLabel } from "./lib/demoScanner.js";
import { makeSummary } from "./lib/localNarrator.js";

const initialReports = makeSeedReports();
const defaultWatchlist = ["secure-bank-update.net", "invoice-pay-secure.org", "crypto-airdrop-bonus.info"];

function firstUrlFromText(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  const explicit = text.match(/https?:\/\/[^\s<>"']+/i)?.[0];
  if (explicit) return explicit.replace(/[),.;]+$/, "");
  const domainLike = text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/i)?.[0];
  return domainLike ? domainLike.replace(/[),.;]+$/, "") : text;
}

function exportReportsCsv(reports) {
  const headers = ["domain", "url", "threat_score", "web_posture_score", "severity", "verdict", "scan_id", "scanned_at"];
  const rows = reports.map((report) => [
    report.domain,
    report.url,
    report.threatScore ?? report.score,
    report.postureScore ?? (typeof report.scoreBreakdown?.security === "number" ? report.scoreBreakdown.security * 4 : ""),
    report.level,
    report.verdict,
    report.id,
    report.scannedAt,
  ]);
  const csv = [headers, ...rows]
    .map((row) => row.map((cell) => `"${String(cell ?? "").replaceAll('"', '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `veilurl-reports-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function App() {
  const [activeView, setActiveView] = useState("scanner");
  const [reports, setReports] = useState(initialReports);
  const [activeReport, setActiveReport] = useState(initialReports[0]);
  const [inputUrl, setInputUrl] = useState(initialReports[0].url);
  const [isScanning, setIsScanning] = useState(false);
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [formError, setFormError] = useState("");
  const [apiStatus, setApiStatus] = useState("checking");
  const [watchlist, setWatchlist] = useState(defaultWatchlist);
  const [watchInput, setWatchInput] = useState("");
  const [toast, setToast] = useState("");

  useEffect(() => {
    let ignore = false;

    async function loadReports() {
      try {
        const payload = await fetchReports();
        if (ignore) return;
        const nextReports = payload.reports?.length ? payload.reports : fallbackReports();
        setReports(nextReports);
        setActiveReport(nextReports[0]);
        setInputUrl(nextReports[0].url);
        setApiStatus(payload.meta?.persistence === "mongodb" ? "mongodb" : "memory-api");
      } catch {
        if (ignore) return;
        const nextReports = fallbackReports();
        setReports(nextReports);
        setActiveReport(nextReports[0]);
        setInputUrl(nextReports[0].url);
        setApiStatus("local-fallback");
      }
    }

    loadReports();

    return () => {
      ignore = true;
    };
  }, []);

  const filteredReports = useMemo(() => {
    return reports.filter((report) => {
      const matchesFilter = filter === "all" || report.level === filter;
      const matchesQuery =
        !query ||
        report.domain.toLowerCase().includes(query.toLowerCase()) ||
        report.id.toLowerCase().includes(query.toLowerCase());
      return matchesFilter && matchesQuery;
    });
  }, [reports, filter, query]);

  async function runScan(event, overrideUrl) {
    event?.preventDefault?.();
    setFormError("");

    let normalized;
    try {
      normalized = normalizeUrl(overrideUrl || inputUrl);
      const parsed = new URL(normalized);
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname.includes(".")) {
        throw new Error("Invalid URL");
      }
      if (overrideUrl) setInputUrl(normalized);
    } catch {
      setFormError("Enter a valid URL, for example https://example.com");
      return;
    }

    setIsScanning(true);
    try {
      const [payload] = await Promise.all([
        scanUrl(normalized),
        new Promise((resolve) => window.setTimeout(resolve, 650)),
      ]);
      const report = payload.report;
      setReports((current) => [report, ...current.filter((item) => item.id !== report.id)].slice(0, 12));
      setActiveReport(report);
      setActiveView("scanner");
      setInputUrl(report.url);
      setApiStatus(payload.meta?.persistence === "mongodb" ? "mongodb" : "memory-api");
    } catch {
      await new Promise((resolve) => window.setTimeout(resolve, 650));
      const report = fallbackScan(normalized);
      setReports((current) => [report, ...current.filter((item) => item.id !== report.id)].slice(0, 12));
      setActiveReport(report);
      setActiveView("scanner");
      setInputUrl(report.url);
      setApiStatus("local-fallback");
    } finally {
      setIsScanning(false);
    }
  }

  function selectReport(report) {
    setActiveReport(report);
    setInputUrl(report.url);
    setActiveView("scanner");
  }

  function handleExport(targetReports) {
    exportReportsCsv(targetReports);
    setToast(`Exported ${targetReports.length} report${targetReports.length === 1 ? "" : "s"} to CSV.`);
    window.setTimeout(() => setToast(""), 2400);
  }

  async function deleteReport(id) {
    try {
      const payload = await deleteReportById(id);
      setApiStatus(payload.meta?.persistence === "mongodb" ? "mongodb" : "memory-api");
    } catch {
      setApiStatus("local-fallback");
    }

    setReports((current) => current.filter((report) => report.id !== id));
    if (activeReport.id === id) {
      const fallback = reports.find((report) => report.id !== id) || fallbackScan("https://vercel.com");
      setActiveReport(fallback);
      setInputUrl(fallback.url);
    }
  }

  return (
    <div className="app-shell">
      <TopNav activeView={activeView} setActiveView={setActiveView} apiStatus={apiStatus} reports={reports} />
      <div className="workspace">
        <SideNav activeView={activeView} setActiveView={setActiveView} />
        <main className="content">
          {activeView === "scanner" && (
            <ScannerView
              report={activeReport}
              reports={reports}
              inputUrl={inputUrl}
              setInputUrl={setInputUrl}
              isScanning={isScanning}
              formError={formError}
              onScan={runScan}
              onDroppedUrl={(value) => runScan(null, firstUrlFromText(value))}
              onSelectReport={selectReport}
              setActiveView={setActiveView}
              apiStatus={apiStatus}
            />
          )}
          {activeView === "history" && (
            <HistoryView
              reports={filteredReports}
              allReports={reports}
              query={query}
              setQuery={setQuery}
              filter={filter}
              setFilter={setFilter}
              onSelectReport={selectReport}
              onDeleteReport={deleteReport}
              onExport={() => handleExport(filteredReports)}
              setActiveView={setActiveView}
            />
          )}
          {activeView === "reports" && (
            <ReportsView reports={reports} activeReport={activeReport} onSelectReport={selectReport} onExport={() => handleExport(reports)} />
          )}
          {activeView === "watchlist" && (
            <WatchlistView
              watchlist={watchlist}
              setWatchlist={setWatchlist}
              watchInput={watchInput}
              setWatchInput={setWatchInput}
              reports={reports}
              setInputUrl={setInputUrl}
              setActiveView={setActiveView}
            />
          )}
          {activeView === "settings" && <SettingsView apiStatus={apiStatus} reports={reports} />}
          {activeView === "keys" && <ApiKeysView apiStatus={apiStatus} />}
          {activeView === "docs" && <DocsView />}
        </main>
      </div>
      <MobileNav activeView={activeView} setActiveView={setActiveView} />
      {toast && (
        <div className="toast" role="status">
          <Check size={17} />
          {toast}
        </div>
      )}
    </div>
  );
}

function TopNav({ activeView, setActiveView, apiStatus, reports }) {
  const [openPanel, setOpenPanel] = useState(null);
  const recentHigh = reports.filter((report) => ["high", "critical"].includes(report.level)).slice(0, 3);
  const persistenceLabel = apiStatus === "mongodb" ? "MongoDB connected" : "Memory mode";

  useEffect(() => {
    setOpenPanel(null);
  }, [activeView]);

  function togglePanel(panel) {
    setOpenPanel((current) => (current === panel ? null : panel));
  }

  return (
    <header className="top-nav">
      <button className="brand" onClick={() => setActiveView("scanner")} aria-label="Go to scanner">
        <span className="brand-mark">
          <ShieldCheck size={25} />
        </span>
        <span>
          Veil<strong>URL</strong>
        </span>
      </button>
      <div className="system-pill">
        <span className="live-dot" />
        Vercel Live
      </div>
      <div className="system-pill hide-sm">
        <Sparkles size={14} />
        All Systems Operational
      </div>
      <nav className="top-links">
        <button className={activeView === "history" ? "active" : ""} onClick={() => setActiveView("history")}>
          <History size={17} />
          History
        </button>
        <button className={activeView === "docs" ? "active" : ""} onClick={() => setActiveView("docs")}>
          <BookOpen size={17} />
          Docs
        </button>
        <button className="icon-button hide-sm" aria-label="Notifications" onClick={() => togglePanel("notifications")}>
          <Bell size={18} />
        </button>
        <button className="avatar" aria-label="User profile" onClick={() => togglePanel("profile")}>
          BK
        </button>
        <button className="icon-button menu-button" aria-label="Menu" onClick={() => togglePanel("menu")}>
          <Menu size={21} />
        </button>
      </nav>
      {openPanel && (
        <div className="top-popover">
          {openPanel === "notifications" && (
            <>
              <div className="popover-title">Security alerts</div>
              {recentHigh.length ? (
                recentHigh.map((report) => (
                  <button key={report.id} className="popover-row" onClick={() => { setActiveView("reports"); setOpenPanel(null); }}>
                    <ShieldAlert size={17} />
                    <span>
                      <strong>{report.domain}</strong>
                      <small>{levelLabel(report.level)} risk report needs review</small>
                    </span>
                  </button>
                ))
              ) : (
                <div className="popover-empty">No high-risk alerts right now.</div>
              )}
            </>
          )}
          {openPanel === "profile" && (
            <>
              <div className="profile-card">
                <span className="avatar large">BK</span>
                <div>
                  <strong>Basil Khowaja</strong>
                  <small>{persistenceLabel}</small>
                </div>
              </div>
              <button className="popover-row" onClick={() => { setActiveView("settings"); setOpenPanel(null); }}>
                <Settings size={17} />
                <span>
                  <strong>Preferences</strong>
                  <small>Runtime and workspace settings</small>
                </span>
              </button>
              <button className="popover-row" onClick={() => { setActiveView("keys"); setOpenPanel(null); }}>
                <KeyRound size={17} />
                <span>
                  <strong>Integrations</strong>
                  <small>MongoDB and future API keys</small>
                </span>
              </button>
            </>
          )}
          {openPanel === "menu" && (
            <>
              <div className="popover-title">Quick navigation</div>
              {[
                ["scanner", ScanSearch, "Scanner"],
                ["reports", FileText, "Reports"],
                ["watchlist", Shield, "Watchlist"],
                ["history", Clock3, "History"],
                ["settings", Settings, "Settings"],
              ].map(([id, Icon, label]) => (
                <button key={id} className="popover-row" onClick={() => { setActiveView(id); setOpenPanel(null); }}>
                  <Icon size={17} />
                  <span>
                    <strong>{label}</strong>
                    <small>{id === "scanner" ? "Run a URL analysis" : `Open ${label.toLowerCase()}`}</small>
                  </span>
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </header>
  );
}

function SideNav({ activeView, setActiveView }) {
  const items = [
    ["scanner", ScanSearch, "Scanner"],
    ["history", Clock3, "History"],
    ["reports", FileText, "Reports"],
    ["watchlist", Shield, "Watchlist"],
    ["settings", Settings, "Settings"],
    ["keys", KeyRound, "API Keys"],
  ];

  return (
    <aside className="side-nav">
      <div className="nav-items">
        {items.map(([id, Icon, label]) => (
          <button
            key={id}
            className={activeView === id || (id === "scanner" && activeView === "scanner") ? "active" : ""}
            onClick={() => setActiveView(id)}
          >
            <Icon size={19} />
            {label}
          </button>
        ))}
      </div>
      <div className="side-card">
        <span>Open source build</span>
        <strong>MERN</strong>
        <div className="meter">
          <span style={{ width: "100%" }} />
        </div>
        <button onClick={() => setActiveView("docs")}>View project docs <ChevronRight size={14} /></button>
      </div>
      <div className="version">
        <span className="live-dot" />
        VeilURL v1.0.0
      </div>
    </aside>
  );
}

function ScannerView({
  report,
  reports,
  inputUrl,
  setInputUrl,
  isScanning,
  formError,
  onScan,
  onDroppedUrl,
  onSelectReport,
  setActiveView,
  apiStatus,
}) {
  const [isDropActive, setIsDropActive] = useState(false);
  const statusText = {
    checking: "Checking backend availability...",
    mongodb: "MongoDB persistence active. Reports are saved across sessions.",
    "memory-api": "Passive recon API active. Add MONGODB_URI to enable persistent history.",
    "local-fallback": "Offline local fallback active. API persistence is unavailable.",
  }[apiStatus];

  return (
    <section className="scanner-grid">
      <div className="scanner-main">
        <form
          className={`scan-form ${isDropActive ? "drop-active" : ""}`}
          onSubmit={onScan}
          onDragEnter={(event) => {
            event.preventDefault();
            setIsDropActive(true);
          }}
          onDragOver={(event) => {
            event.preventDefault();
            event.dataTransfer.dropEffect = "copy";
            setIsDropActive(true);
          }}
          onDragLeave={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) {
              setIsDropActive(false);
            }
          }}
          onDrop={(event) => {
            event.preventDefault();
            setIsDropActive(false);
            const payload =
              event.dataTransfer.getData("text/uri-list") ||
              event.dataTransfer.getData("text/plain");
            onDroppedUrl(payload);
          }}
        >
          <div className={`url-field ${formError ? "error" : ""}`}>
            <Globe2 size={22} />
            <input
              value={inputUrl}
              onChange={(event) => setInputUrl(event.target.value)}
              aria-label="URL to scan"
              placeholder="https://example.com"
            />
            {inputUrl && (
              <button type="button" onClick={() => setInputUrl("")} aria-label="Clear URL">
                <X size={20} />
              </button>
            )}
          </div>
          <button className="primary-button" type="submit" disabled={isScanning}>
            {isScanning ? <RefreshCw className="spin" size={19} /> : <ScanSearch size={19} />}
            {isScanning ? "Scanning" : "Scan URL"}
          </button>
        </form>
        <div className="form-subline">
          <span className={formError ? "form-error" : ""}>
            {formError || statusText}
          </span>
          <button className="text-button" onClick={() => setActiveView("docs")}>
            <Info size={15} />
            How scoring works
          </button>
        </div>
        {isScanning ? <ScanningPanel /> : <ReportPanel report={report} onRescan={onScan} />}
      </div>
      <RecentScans reports={reports} onSelectReport={onSelectReport} setActiveView={setActiveView} />
    </section>
  );
}

function ScanningPanel() {
  const stages = [
    ["Normalize URL", Link2],
    ["Passive DNS", Globe2],
    ["TLS posture", LockKeyhole],
    ["Local signals", ShieldAlert],
    ["Analyst summary", FileText],
  ];

  return (
    <div className="scan-progress panel">
      <div className="target-orb">
        <ScanSearch size={40} />
      </div>
      <h1>Scanning URL</h1>
      <p>Building a concise passive recon report from public URL signals.</p>
      <div className="pipeline">
        {stages.map(([label, Icon], index) => (
          <div className={`pipeline-step ${index < 2 ? "complete" : index === 2 ? "running" : ""}`} key={label}>
            <span>
              <Icon size={18} />
            </span>
            <strong>{label}</strong>
            <small>{index < 2 ? "Complete" : index === 2 ? "Running" : "Queued"}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReportPanel({ report, onRescan }) {
  const [activeTab, setActiveTab] = useState("Overview");
  const tabs = ["Overview", "WHOIS", "DNS", "TLS", "Redirects", "Headers", "Reputation"];
  const breakdown = [
    ["Domain", report.scoreBreakdown.domain],
    ["Web posture", report.scoreBreakdown.security],
    ["Local signals", report.scoreBreakdown.reputation],
    ["Content", report.scoreBreakdown.content],
  ];

  return (
    <div className="report-stack">
      <section className="report-hero panel">
        <div className="risk-block">
          <div className="section-title">
            <span>Threat score</span>
            <Info size={15} />
          </div>
          <RiskGauge score={report.score} level={report.level} />
        </div>
        <div className="verdict-block">
          <div className="section-title">
            <span>Verdict</span>
            <Info size={15} />
          </div>
          <h1>{report.level === "low" ? "Low risk" : levelLabel(report.level) + " risk"}</h1>
          <div className="verdict-alert">
            {report.level === "low" ? <ShieldCheck size={34} /> : <ShieldAlert size={34} />}
            <div>
              <strong>{report.verdict}</strong>
                <p>
                  {report.level === "low"
                  ? "No immediate action is needed for this report."
                  : "This URL shows indicators that may pose a threat to users."}
                </p>
            </div>
          </div>
        </div>
        <div className="scan-facts">
          <Fact label="Scanned" value="15 Jun 2026, 10:24 AM" />
          <Fact label="Scan ID" value={report.id} copy />
          <Fact label="IP address" value={report.ip} copy />
          <Fact label="Server" value={report.server} />
          <Fact label="Response time" value={`${report.responseMs} ms`} />
        </div>
        <div className="score-bars">
          {breakdown.map(([label, value]) => (
            <div className="score-bar" key={label}>
              <span>{label}</span>
              <div>
                <i style={{ width: `${value * 4}%` }} />
              </div>
              <strong>{value}/25</strong>
            </div>
          ))}
        </div>
      </section>

      <div className="report-tabs">
        {tabs.map((tab) => (
          <button key={tab} className={activeTab === tab ? "active" : ""} onClick={() => setActiveTab(tab)}>
            {tab}
          </button>
        ))}
      </div>

      <ReportTabContent activeTab={activeTab} report={report} onRescan={onRescan} />
    </div>
  );
}

function reconData(report, key) {
  return report.recon?.[key]?.data || null;
}

function compactList(items, fallback = "Not observed", limit = 2) {
  const clean = (items || []).filter(Boolean);
  if (!clean.length) return fallback;
  const shown = clean.slice(0, limit).join(", ");
  return clean.length > limit ? `${shown} +${clean.length - limit} more` : shown;
}

function readableDate(value, fallback = "Not available") {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return date.toLocaleDateString("en", { day: "2-digit", month: "short", year: "numeric" });
}

function passWarnFail(condition, warnCondition = false) {
  if (condition) return "fail";
  if (warnCondition) return "warn";
  return "pass";
}

function ReportTabContent({ activeTab, report, onRescan }) {
  const rdap = reconData(report, "rdap");
  const dns = reconData(report, "dns");
  const http = reconData(report, "http");
  const tls = reconData(report, "tls");
  const securityTxt = reconData(report, "securityTxt");
  const robotsTxt = reconData(report, "robotsTxt");

  const whoisContent = (
    <DataRows
      rows={[
        ["Domain", report.domain],
        ["Registrar", rdap?.registrar || "Not available"],
        ["Registered on", readableDate(rdap?.registeredAt, `${report.registeredDays} days ago`)],
        ["Expires in", typeof rdap?.expiresDays === "number" ? `${rdap.expiresDays} days` : `${report.expiresDays} days`],
        ["RDAP status", rdap?.found ? "Found" : rdap?.error || "Not available"],
        ["Name servers", compactList(rdap?.nameservers || dns?.ns, "Not observed", 3)],
      ]}
    />
  );
  const dnsContent = (
    <DataRows
      rows={[
        ["A record", compactList(dns?.a, report.ip, 3)],
        ["AAAA record", compactList(dns?.aaaa, "Not observed", 2)],
        ["NS", compactList(dns?.ns, "Not observed", 3)],
        ["MX", compactList(dns?.mx?.map((record) => `${record.priority} ${record.exchange}`), `10 mail.${report.domain}`, 2)],
        ["SPF", dns?.spf?.present ? "Present" : "Not observed"],
        ["DMARC", dns?.dmarc?.present ? "Present" : "Not observed"],
      ]}
    />
  );
  const tlsContent = (
    <DataRows
      rows={[
        ["Issuer", tls?.issuer || "Not available"],
        ["Subject", tls?.subject || report.domain],
        ["Valid from", readableDate(tls?.validFrom)],
        ["Valid to", readableDate(tls?.validTo, `${report.expiresDays} days remaining`)],
        ["Days remaining", typeof tls?.daysRemaining === "number" ? `${tls.daysRemaining}` : "Not available"],
        ["SAN names", compactList(tls?.san, "Not observed", 2)],
      ]}
    />
  );
  const redirectsContent = <RedirectChain report={report} />;
  const headersContent = <HeaderList report={report} />;
  const reputationContent = <ReputationList report={report} />;

  const rdapStatus = passWarnFail(false, !rdap?.found);
  const dnsStatus = passWarnFail(false, Boolean(dns?.mailSecurity?.mxPresent && (!dns.mailSecurity.spfPresent || !dns.mailSecurity.dmarcPresent)));
  const tlsStatus = passWarnFail(tls?.expired || tls?.available === false, tls?.expiringSoon);
  const headerStatus = passWarnFail(report.headerMisses > 3, report.headerMisses > 1);
  const redirectStatus = passWarnFail(http?.crossDomain, report.redirectCount > 2);

  const panels = {
    WHOIS: (
      <FocusedSignalView
        title="WHOIS registration profile"
        description="Registration age, registrar, privacy posture, and domain ownership signals."
        icon={Database}
        status={rdapStatus}
        primary={whoisContent}
        findings={[
          rdap?.found ? "RDAP returned public registration metadata for this domain." : "RDAP did not return a public registration profile.",
          report.registeredDays < 120 ? "Recently registered domain deserves extra scrutiny." : "Domain age is not unusually new.",
          `Top-level domain: .${report.tld}`,
        ]}
      />
    ),
    DNS: (
      <FocusedSignalView
        title="DNS record posture"
        description="Resolved records, mail exchange, TTL, and name server configuration."
        icon={Globe2}
        status={dnsStatus}
        primary={dnsContent}
        findings={[
          dns?.a?.length ? `${dns.a.length} IPv4 record${dns.a.length === 1 ? "" : "s"} observed.` : "No IPv4 A record was observed.",
          dns?.mailSecurity?.mxPresent ? "MX records are present for domain mail routing." : "No MX records were observed.",
          dns?.mailSecurity?.mxPresent && (!dns.mailSecurity.spfPresent || !dns.mailSecurity.dmarcPresent)
            ? "Mail DNS exists but SPF or DMARC is missing."
            : "Mail authentication DNS posture has no obvious passive gap.",
        ]}
      />
    ),
    TLS: (
      <FocusedSignalView
        title="TLS certificate posture"
        description="Certificate issuer, validity window, protocol, and transparency checks."
        icon={LockKeyhole}
        status={tlsStatus}
        primary={tlsContent}
        findings={[
          tls?.available === false ? "TLS certificate details were not available for this target." : "TLS certificate details were collected from port 443.",
          tls?.expired ? "Certificate is expired." : tls?.expiringSoon ? "Certificate renewal window is getting close." : "Certificate validity window is acceptable.",
          tls?.authorized ? "Certificate chain is trusted by the runtime." : tls?.authorizationError ? `Trust note: ${tls.authorizationError}` : "Trust status was not reported.",
        ]}
      />
    ),
    Redirects: (
      <FocusedSignalView
        title="Redirect chain"
        description="Observed hops from initial request to final destination."
        icon={RotateCcw}
        status={report.redirectCount > 2 ? "warn" : "pass"}
        primary={redirectsContent}
        findings={[
          `${report.redirectCount} redirect hop${report.redirectCount === 1 ? "" : "s"} observed for this URL.`,
          report.redirectCount > 2 ? "Multiple hops can hide the final destination from users." : "Redirect chain is short and readable.",
          http?.crossDomain ? "The final host differs from the starting host." : "No cross-domain final hop was observed.",
        ]}
      />
    ),
    Headers: (
      <FocusedSignalView
        title="HTTP security headers"
        description="Browser-side protections that reduce common web exploitation risk."
        icon={Archive}
        status={headerStatus}
        primary={headersContent}
        findings={[
          `${report.headerMisses} important header${report.headerMisses === 1 ? "" : "s"} missing in this passive check.`,
          securityTxt?.found ? "security.txt is published for coordinated disclosure." : "security.txt was not found.",
          robotsTxt?.found ? `robots.txt found with ${robotsTxt.disallowCount} disallow rule${robotsTxt.disallowCount === 1 ? "" : "s"}.` : "robots.txt was not found.",
        ]}
      />
    ),
    Reputation: (
      <FocusedSignalView
        title="Reputation signals"
        description="Local keyword, posture, and reputation indicators. External reputation APIs are not connected yet."
        icon={ShieldAlert}
        status={report.reputationHits ? "fail" : "pass"}
        primary={reputationContent}
        findings={[
          report.reputationHits ? `${report.reputationHits} local reputation hit${report.reputationHits === 1 ? "" : "s"} found.` : "No local reputation hits were found.",
          report.keywordHits.length ? `Keyword signals: ${report.keywordHits.join(", ")}` : "No suspicious keyword pattern detected.",
          report.reputationHits ? "Treat this destination cautiously until verified." : "No local reputation or keyword concerns were raised.",
        ]}
      />
    ),
  };

  if (activeTab !== "Overview") {
    return <section className="focused-tab-layout">{panels[activeTab]}</section>;
  }

  return (
    <section className="report-layout">
      <div className="signal-grid">
        <SignalPanel title="WHOIS summary" icon={Database} status={rdapStatus}>
          {whoisContent}
        </SignalPanel>
        <SignalPanel title="DNS records" icon={Globe2} status={dnsStatus}>
          {dnsContent}
        </SignalPanel>
        <SignalPanel title="TLS certificate" icon={LockKeyhole} status={tlsStatus}>
          {tlsContent}
        </SignalPanel>
        <SignalPanel title="Redirect chain" icon={RotateCcw} status={redirectStatus}>
          {redirectsContent}
        </SignalPanel>
        <SignalPanel title="Header posture" icon={Archive} status={headerStatus}>
          {headersContent}
        </SignalPanel>
        <SignalPanel title="Reputation signals" icon={ShieldAlert} status={report.reputationHits ? "fail" : "pass"}>
          {reputationContent}
        </SignalPanel>
      </div>
      <aside className="analyst-column">
        <AnalystSummaryPanel report={report} />
        <ActionsPanel onRescan={onRescan} />
      </aside>
    </section>
  );
}

function FocusedSignalView({ title, description, icon: Icon, status, primary, findings }) {
  return (
    <>
      <div className="panel focused-signal">
        <div className="focused-heading">
          <span>
            <Icon size={22} />
            <strong>{title}</strong>
          </span>
          <StatusBadge status={status} />
        </div>
        <p>{description}</p>
        <div className="focused-body">{primary}</div>
      </div>
      <aside className="panel focused-findings">
        <div className="panel-heading">
          <span>
            <Sparkles size={18} />
            Signal interpretation
          </span>
        </div>
        <ul>
          {findings.map((finding) => (
            <li key={finding}>{finding}</li>
          ))}
        </ul>
      </aside>
    </>
  );
}

function AnalystSummaryPanel({ report }) {
  return (
    <div className="panel analyst-panel">
      <div className="panel-heading">
        <span>
          <Sparkles size={18} />
          Analyst summary
        </span>
      </div>
      <p>{makeSummary(report)}</p>
      <ul>
        {(report.keywordHits.length
          ? report.keywordHits.slice(0, 4).map((word) => `Keyword signal: ${word}`)
          : ["No suspicious keyword pattern", "Stable domain posture", "Low local reputation noise"]
        ).map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function ActionsPanel({ onRescan }) {
  return (
    <div className="panel actions-panel">
      <div className="panel-heading">
        <span>
          <Shield size={18} />
          Recommended actions
        </span>
      </div>
      <ActionItem title="Do not submit sensitive data" detail="Avoid entering passwords, tokens, or payment details." />
      <ActionItem title="Block this URL" detail="Add to security filters and DNS blocklists if needed." />
      <ActionItem title="Report this site" detail="Notify your security team or hosting provider." />
      <ActionItem title="Monitor for changes" detail="Re-scan this URL periodically." />
      <button className="secondary-button" onClick={onRescan}>
        <RefreshCw size={17} />
        Re-scan this URL
      </button>
    </div>
  );
}

function RiskGauge({ score, level }) {
  const degrees = Math.round((score / 100) * 280);
  return (
    <div className={`risk-gauge ${level}`}>
      <div
        className="gauge-ring"
        style={{
          background: `conic-gradient(var(--risk-color) ${degrees}deg, #e8edf5 ${degrees}deg 360deg)`,
        }}
      >
        <span>
          <strong>{score}</strong>
          <small>/100</small>
        </span>
      </div>
      <SeverityChip level={level} />
    </div>
  );
}

function Fact({ label, value, copy }) {
  return (
    <div className="fact-row">
      <span>{label}</span>
      <strong>
        {value}
        {copy && <Copy size={13} />}
      </strong>
    </div>
  );
}

function SignalPanel({ title, icon: Icon, status, children }) {
  return (
    <div className="panel signal-panel">
      <div className="panel-heading">
        <span>
          <Icon size={17} />
          {title}
        </span>
        <StatusBadge status={status} />
      </div>
      {children}
    </div>
  );
}

function DataRows({ rows }) {
  return (
    <div className="data-rows">
      {rows.map(([label, value]) => (
        <div key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function RedirectChain({ report }) {
  const hops = reconData(report, "http")?.hops;
  const rows = hops?.length
    ? hops.map((hop, index) => [
        hop.url,
        hop.error ? hop.error : `${hop.status || "No"} ${hop.location ? `-> ${hop.location}` : "response"}`,
        hop.error ? "fail" : hop.status >= 300 && hop.status < 400 ? "warn" : index === hops.length - 1 ? "pass" : "warn",
      ])
    : [
        [`https://${report.domain}`, "301 Moved Permanently", "pass"],
        [`https://www.${report.domain}`, "302 Found", "warn"],
        [report.redirectCount > 2 ? "https://secure-verify-account.net/final" : report.url, "200 OK", report.redirectCount > 2 ? "fail" : "pass"],
      ];

  return (
    <div className="redirect-chain">
      {rows.map(([url, meta, state]) => (
        <div className="redirect-row" key={`${url}-${meta}`}>
          <CircleDot className={state} size={15} />
          <div>
            <strong>{url}</strong>
            <span>{meta}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function HeaderList({ report }) {
  const headerChecks = reconData(report, "http")?.headers?.checks;
  const securityTxt = reconData(report, "securityTxt");
  const robotsTxt = reconData(report, "robotsTxt");
  const fallbackRows = [
    ["Strict-Transport-Security", report.headerMisses < 2],
    ["Content-Security-Policy", report.headerMisses < 1],
    ["X-Frame-Options", report.headerMisses < 3],
    ["X-Content-Type-Options", true],
    ["Referrer-Policy", report.headerMisses < 4],
    ["Permissions-Policy", report.headerMisses < 2],
  ];
  const rows = headerChecks?.length
    ? headerChecks.map((check) => [check.name.replaceAll("-", " "), check.present])
    : fallbackRows;

  return (
    <div className="header-list">
      {rows.map(([label, ok]) => (
        <div key={label}>
          <span>{label}</span>
          {ok ? <Check className="pass" size={16} /> : <X className="fail" size={16} />}
        </div>
      ))}
      {(securityTxt || robotsTxt) && (
        <>
          <div>
            <span>security.txt</span>
            {securityTxt?.found ? <Check className="pass" size={16} /> : <X className="fail" size={16} />}
          </div>
          <div>
            <span>robots.txt</span>
            {robotsTxt?.found ? <Check className="pass" size={16} /> : <X className="fail" size={16} />}
          </div>
        </>
      )}
    </div>
  );
}

function ReputationList({ report }) {
  const rows = [
    ["Local keyword model", report.keywordHits.length ? report.keywordHits.join(", ") : "No keyword hit", report.keywordHits.length ? "warn" : "pass"],
    ["Local reputation model", report.reputationHits ? `${report.reputationHits} hit estimate` : "No hit", report.reputationHits ? "fail" : "pass"],
    ["External reputation APIs", "Not connected", "warn"],
    ["Security.txt", reconData(report, "securityTxt")?.found ? "Published" : "Not found", reconData(report, "securityTxt")?.found ? "pass" : "warn"],
    ["Robots.txt", reconData(report, "robotsTxt")?.found ? "Published" : "Not found", reconData(report, "robotsTxt")?.found ? "pass" : "warn"],
  ];

  return (
    <div className="reputation-list">
      {rows.map(([name, label, state]) => (
        <div key={name}>
          <span>{name}</span>
          <StatusBadge status={state} label={label} />
        </div>
      ))}
    </div>
  );
}

function ActionItem({ title, detail }) {
  return (
    <button className="action-item">
      <ShieldCheck size={17} />
      <span>
        <strong>{title}</strong>
        <small>{detail}</small>
      </span>
      <ChevronRight size={17} />
    </button>
  );
}

function RecentScans({ reports, onSelectReport, setActiveView }) {
  return (
    <aside className="recent-panel panel">
      <div className="recent-heading">
        <span>
          <Sparkles size={18} />
          Recent scans
        </span>
        <button aria-label="Filter scans">
          <Filter size={18} />
        </button>
      </div>
      <div className="recent-list">
        {reports.slice(0, 10).map((report) => (
          <button key={report.id} className={`recent-item ${report.level}`} onClick={() => onSelectReport(report)}>
            <MiniScore report={report} />
            <span>
              <strong>{report.domain}</strong>
              <small>
                <span className={`dot ${report.level}`} />
                {levelLabel(report.level)}
              </small>
            </span>
            <em>{report.scannedAt}</em>
            <ChevronRight size={16} />
          </button>
        ))}
      </div>
      <button className="secondary-button" onClick={() => setActiveView("history")}>
        <Clock3 size={17} />
        View full history
      </button>
    </aside>
  );
}

function MiniScore({ report }) {
  return (
    <span className={`mini-score ${report.level}`}>
      <strong>{report.score}</strong>
    </span>
  );
}

function HistoryView({
  reports,
  allReports,
  query,
  setQuery,
  filter,
  setFilter,
  onSelectReport,
  onDeleteReport,
  onExport,
  setActiveView,
}) {
  const counts = useMemo(() => {
    return allReports.reduce(
      (acc, report) => {
        acc[report.level] += 1;
        return acc;
      },
      { low: 0, medium: 0, high: 0, critical: 0 }
    );
  }, [allReports]);
  const total = allReports.length || 1;

  return (
    <section className="history-view">
      <div className="page-heading">
        <div>
          <h1>Scan history</h1>
          <p>View, filter, and reopen URL security reports.</p>
        </div>
        <div className="heading-actions">
          <button className="ghost-button" onClick={onExport}>
            <Download size={17} />
            Export CSV
          </button>
          <button className="primary-button" onClick={() => setActiveView("scanner")}>
            <ScanSearch size={17} />
            New scan
          </button>
        </div>
      </div>
      <div className="history-layout">
        <div className="history-main">
          <div className="history-filters">
            <label className="search-field">
              <Search size={18} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search domain or report ID..."
              />
            </label>
            <div className="segmented-filter">
              {["all", "low", "medium", "high", "critical"].map((item) => (
                <button key={item} className={filter === item ? "active" : ""} onClick={() => setFilter(item)}>
                  {item === "all" ? "All severity" : levelLabel(item)}
                </button>
              ))}
            </div>
          </div>
          <div className="history-table panel">
            <div className="table-row table-head">
              <span>URL / Domain</span>
              <span>Risk Score</span>
              <span>Severity</span>
              <span>Verdict</span>
              <span>Created</span>
              <span>Report ID</span>
              <span>Actions</span>
            </div>
            {reports.map((report) => (
              <div className="table-row" key={report.id}>
                <span className="domain-cell">
                  <Globe2 size={17} />
                  <button onClick={() => onSelectReport(report)}>
                    <strong>{report.domain}</strong>
                    <small>{report.url}</small>
                  </button>
                </span>
                <span>
                  <MiniScore report={report} />
                </span>
                <span>
                  <SeverityChip level={report.level} />
                </span>
                <span>
                  <strong>{report.verdict}</strong>
                  <small>{report.level === "low" ? "No action needed" : "Review recommended"}</small>
                </span>
                <span>{report.scannedAt}</span>
                <span className="report-id">{report.id}</span>
                <span className="row-actions">
                  <button onClick={() => onSelectReport(report)} aria-label={`Open ${report.domain}`}>
                    <Eye size={16} />
                  </button>
                  <button onClick={() => onDeleteReport(report.id)} aria-label={`Delete ${report.domain}`}>
                    <Trash2 size={16} />
                  </button>
                </span>
              </div>
            ))}
          </div>
        </div>
        <aside className="insights panel">
          <div className="panel-heading">
            <span>Insights</span>
          </div>
          <div className="donut-wrap">
            <div
              className="donut"
              style={{
                background: `conic-gradient(#dc2626 0 ${counts.critical / total}turn, #f97316 0 ${
                  (counts.critical + counts.high) / total
                }turn, #f59e0b 0 ${(counts.critical + counts.high + counts.medium) / total}turn, #22a06b 0 1turn)`,
              }}
            >
              <span>
                <strong>{allReports.length}</strong>
                Total scans
              </span>
            </div>
          </div>
          <InsightRow label="Critical" value={counts.critical} />
          <InsightRow label="High" value={counts.high} />
          <InsightRow label="Medium" value={counts.medium} />
          <InsightRow label="Low" value={counts.low} />
          <div className="common-findings">
            <h3>Common findings</h3>
            <InsightRow label="Suspicious domain name" value={18} />
            <InsightRow label="Low domain age" value={16} />
            <InsightRow label="Missing security headers" value={10} />
            <InsightRow label="Uses IP address" value={6} />
          </div>
        </aside>
      </div>
    </section>
  );
}

function ReportsView({ reports, activeReport, onSelectReport, onExport }) {
  const highRisk = reports.filter((report) => ["high", "critical"].includes(report.level));

  return (
    <section className="reports-view">
      <div className="page-heading">
        <div>
          <h1>Report library</h1>
          <p>Curated security reports with analyst summaries and action status.</p>
        </div>
        <div className="heading-actions">
          <button className="ghost-button" onClick={onExport}>
            <Download size={17} />
            Export reports
          </button>
        </div>
      </div>
      <div className="utility-grid">
        <div className="utility-main">
          <div className="metric-strip">
            <MetricCard label="Saved reports" value={reports.length} icon={FileText} />
            <MetricCard label="High risk" value={highRisk.length} icon={ShieldAlert} tone="danger" />
            <MetricCard label="Clean domains" value={reports.filter((report) => report.level === "low").length} icon={ShieldCheck} tone="safe" />
          </div>
          <div className="report-card-grid">
            {reports.map((report) => (
              <button key={report.id} className="report-card panel" onClick={() => onSelectReport(report)}>
                <div>
                  <MiniScore report={report} />
                  <SeverityChip level={report.level} />
                </div>
                <strong>{report.domain}</strong>
                <span>{report.verdict}</span>
                <small>{report.id}</small>
              </button>
            ))}
          </div>
        </div>
        <aside className="panel detail-drawer">
          <div className="panel-heading">
            <span>
              <FileText size={18} />
              Selected report
            </span>
          </div>
          <div className="drawer-body">
            <h2>{activeReport.domain}</h2>
            <SeverityChip level={activeReport.level} />
            <p>{makeSummary(activeReport)}</p>
            <DataRows
              rows={[
                ["Threat score", `${activeReport.threatScore ?? activeReport.score}/100`],
                ["Web posture", `${activeReport.postureScore ?? activeReport.scoreBreakdown.security * 4}/100`],
                ["Scan ID", activeReport.id],
                ["Server", activeReport.server],
                ["Response", `${activeReport.responseMs} ms`],
                ["Signals", `${activeReport.keywordHits.length} keyword hits`],
              ]}
            />
          </div>
        </aside>
      </div>
    </section>
  );
}

function WatchlistView({ watchlist, setWatchlist, watchInput, setWatchInput, reports, setInputUrl, setActiveView }) {
  function addWatchItem(event) {
    event.preventDefault();
    const domain = watchInput.trim().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "");
    if (!domain || watchlist.includes(domain)) return;
    setWatchlist((current) => [domain, ...current]);
    setWatchInput("");
  }

  return (
    <section className="watchlist-view">
      <div className="page-heading">
        <div>
          <h1>Watchlist</h1>
          <p>Keep suspicious or important domains one click away for repeat scans.</p>
        </div>
      </div>
      <div className="utility-grid">
        <div className="utility-main">
          <form className="watch-form panel" onSubmit={addWatchItem}>
            <label className="search-field">
              <Globe2 size={18} />
              <input value={watchInput} onChange={(event) => setWatchInput(event.target.value)} placeholder="Add domain, e.g. example.com" />
            </label>
            <button className="primary-button" type="submit">
              <Plus size={17} />
              Add domain
            </button>
          </form>
          <div className="watch-list panel">
            {watchlist.map((domain) => {
              const lastReport = reports.find((report) => report.domain === domain);
              return (
                <div className="watch-row" key={domain}>
                  <span>
                    <Globe2 size={18} />
                    <strong>{domain}</strong>
                  </span>
                  {lastReport ? <SeverityChip level={lastReport.level} /> : <StatusBadge status="warn" label="Not scanned" />}
                  <button
                    className="ghost-button"
                    onClick={() => {
                      setInputUrl(`https://${domain}`);
                      setActiveView("scanner");
                    }}
                  >
                    <ScanSearch size={16} />
                    Scan
                  </button>
                  <button className="icon-button" onClick={() => setWatchlist((current) => current.filter((item) => item !== domain))} aria-label={`Remove ${domain}`}>
                    <Trash2 size={16} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
        <aside className="panel detail-drawer">
          <div className="panel-heading">
            <span>
              <Shield size={18} />
              Watchlist behavior
            </span>
          </div>
          <div className="drawer-body">
            <p>
              This MVP stores a local review list for domains you want to rescan. The next backend step can persist this list per user or project.
            </p>
            <DataRows rows={[["Tracked domains", watchlist.length], ["Quick scan", "Enabled"], ["Auto monitoring", "Planned"]]} />
          </div>
        </aside>
      </div>
    </section>
  );
}

function SettingsView({ apiStatus, reports }) {
  const [settings, setSettings] = useState({
    compact: true,
    demoNotice: true,
    reducedMotion: false,
  });

  function toggleSetting(key) {
    setSettings((current) => ({ ...current, [key]: !current[key] }));
  }

  return (
    <section className="settings-view">
      <div className="page-heading">
        <div>
          <h1>Settings</h1>
          <p>Workspace preferences and runtime health for the local build.</p>
        </div>
      </div>
      <div className="settings-grid">
        <SettingPanel title="Runtime" icon={Database}>
          <DataRows
            rows={[
              ["Persistence", apiStatus === "mongodb" ? "MongoDB active" : "Local fallback"],
              ["Saved reports", reports.length],
              ["Frontend", "React + Vite"],
              ["Backend", "Vercel API routes"],
            ]}
          />
        </SettingPanel>
        <SettingPanel title="Interface" icon={Settings}>
          <ToggleRow label="Compact dashboard density" checked={settings.compact} onToggle={() => toggleSetting("compact")} />
          <ToggleRow label="Show passive-analysis notice" checked={settings.demoNotice} onToggle={() => toggleSetting("demoNotice")} />
          <ToggleRow label="Reduce decorative motion" checked={settings.reducedMotion} onToggle={() => toggleSetting("reducedMotion")} />
        </SettingPanel>
        <SettingPanel title="Data handling" icon={Archive}>
          <DataRows rows={[["CSV export", "Enabled"], ["Delete reports", "Enabled"], ["Public sharing", "Not enabled"]]} />
        </SettingPanel>
      </div>
    </section>
  );
}

function ApiKeysView({ apiStatus }) {
  return (
    <section className="keys-view">
      <div className="page-heading">
        <div>
          <h1>API keys & integrations</h1>
          <p>Integration readiness without exposing secrets in the browser.</p>
        </div>
      </div>
      <div className="settings-grid">
        <IntegrationCard title="MongoDB Atlas" status={apiStatus === "mongodb" ? "Connected" : "Not connected"} icon={Database} active={apiStatus === "mongodb"} />
        <IntegrationCard title="WHOIS / RDAP" status="Connected" icon={Globe2} active />
        <IntegrationCard title="Reputation APIs" status="Planned" icon={ShieldAlert} />
        <IntegrationCard title="AI report narration" status="Planned" icon={Sparkles} />
      </div>
      <div className="panel doc-panel wide">
        <h2>Secret handling</h2>
        <p>
          API keys belong in server-side environment variables only. The frontend should call protected API routes, never third-party services directly.
        </p>
      </div>
    </section>
  );
}

function MetricCard({ label, value, icon: Icon, tone = "" }) {
  return (
    <div className={`metric-card panel ${tone}`}>
      <Icon size={20} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SettingPanel({ title, icon: Icon, children }) {
  return (
    <div className="panel setting-panel">
      <div className="panel-heading">
        <span>
          <Icon size={18} />
          {title}
        </span>
      </div>
      <div className="drawer-body">{children}</div>
    </div>
  );
}

function ToggleRow({ label, checked = false, onToggle }) {
  return (
    <div className="toggle-row">
      <span>{label}</span>
      <button className={`switch ${checked ? "on" : ""}`} onClick={onToggle} aria-pressed={checked} aria-label={label}>
        <i />
      </button>
    </div>
  );
}

function IntegrationCard({ title, status, icon: Icon, active = false }) {
  return (
    <div className={`panel integration-card ${active ? "active" : ""}`}>
      <Icon size={22} />
      <div>
        <strong>{title}</strong>
        <span>{status}</span>
      </div>
      {active ? <Check size={18} /> : <ExternalLink size={18} />}
    </div>
  );
}

function InsightRow({ label, value }) {
  return (
    <div className="insight-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function DocsView() {
  return (
    <section className="docs-view">
      <div className="page-heading">
        <div>
          <h1>Project docs</h1>
          <p>A clean technical overview for employers reviewing the project.</p>
        </div>
      </div>
      <div className="docs-grid">
        <div className="panel doc-panel wide">
          <h2>Architecture</h2>
          <p>
            VeilURL is designed as a MERN-style Vercel application. The scanner uses Vercel API routes for passive
            recon, stores report history in MongoDB Atlas, and keeps third-party or secret-backed integrations server-side.
          </p>
          <div className="architecture-flow">
            <span>React JSX</span>
            <ChevronRight size={17} />
            <span>Vercel API</span>
            <ChevronRight size={17} />
            <span>Passive recon</span>
            <ChevronRight size={17} />
            <span>MongoDB Atlas</span>
          </div>
        </div>
        <div className="panel doc-panel">
          <h2>MVP scope</h2>
          <p>URL reports are generated from passive public signals: DNS, RDAP, redirects, HTTP headers, TLS, and well-known files.</p>
        </div>
        <div className="panel doc-panel">
          <h2>Future integrations</h2>
          <p>Google Safe Browsing, VirusTotal, PDF export, scheduled monitoring, and AI report narration.</p>
        </div>
      </div>
    </section>
  );
}

function StatusBadge({ status, label }) {
  const text = label || { pass: "Pass", warn: "Warn", fail: "Fail" }[status];
  return <span className={`status-badge ${status}`}>{text}</span>;
}

function SeverityChip({ level }) {
  return <span className={`severity-chip ${level}`}>{levelLabel(level)}</span>;
}

function MobileNav({ activeView, setActiveView }) {
  return (
    <nav className="mobile-nav">
      <button className={activeView === "scanner" ? "active" : ""} onClick={() => setActiveView("scanner")}>
        <ScanSearch size={20} />
        Scan
      </button>
      <button className={activeView === "history" ? "active" : ""} onClick={() => setActiveView("history")}>
        <Clock3 size={20} />
        History
      </button>
      <button className={activeView === "docs" ? "active" : ""} onClick={() => setActiveView("docs")}>
        <BookOpen size={20} />
        Docs
      </button>
      <button className={activeView === "settings" ? "active" : ""} onClick={() => setActiveView("settings")}>
        <Settings size={20} />
        Settings
      </button>
    </nav>
  );
}

export default App;
