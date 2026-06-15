import { fetchSmallText } from "./http.js";

function extractLine(text, key) {
  const lower = key.toLowerCase();
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.toLowerCase().startsWith(`${lower}:`)) || "";
}

export async function collectSecurityTxt(origin) {
  const result = await fetchSmallText(new URL("/.well-known/security.txt", origin).toString());
  return {
    found: result.found,
    status: result.status,
    finalUrl: result.finalUrl || "",
    hops: result.hops || [],
    contact: result.found ? extractLine(result.text, "Contact") : "",
    expires: result.found ? extractLine(result.text, "Expires") : "",
    policy: result.found ? extractLine(result.text, "Policy") : "",
    error: result.error || "",
  };
}

export async function collectRobotsTxt(origin) {
  const result = await fetchSmallText(new URL("/robots.txt", origin).toString());
  const lines = result.text.split(/\r?\n/).map((line) => line.trim());
  return {
    found: result.found,
    status: result.status,
    finalUrl: result.finalUrl || "",
    hops: result.hops || [],
    disallowCount: result.found ? lines.filter((line) => /^disallow:/i.test(line)).length : 0,
    sitemapCount: result.found ? lines.filter((line) => /^sitemap:/i.test(line)).length : 0,
    error: result.error || "",
  };
}
