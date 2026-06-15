import { makeReport, makeSeedReports } from "./demoScanner.js";

async function parseJson(response) {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed with ${response.status}`);
  }
  return payload;
}

export async function fetchReports({ severity = "all", search = "", page = 1 } = {}) {
  const params = new URLSearchParams();
  if (severity && severity !== "all") params.set("severity", severity);
  if (search) params.set("search", search);
  params.set("page", String(page));

  const response = await fetch(`/api/reports?${params.toString()}`);
  return parseJson(response);
}

export async function scanUrl(url) {
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  return parseJson(response);
}

export async function deleteReportById(id) {
  const response = await fetch(`/api/reports/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  return parseJson(response);
}

export function fallbackReports() {
  return makeSeedReports();
}

export function fallbackScan(url) {
  return makeReport(url);
}
