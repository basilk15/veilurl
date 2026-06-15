import { z } from "zod";
import { makeReport, normalizeUrl } from "../src/lib/demoScanner.js";
import { makeSummary } from "../src/lib/localNarrator.js";
import { methodNotAllowed, persistenceMeta, sendJson } from "./_lib/http.js";
import { enrichReportWithRecon } from "./_lib/recon/enrichReport.js";
import { runPassiveRecon } from "./_lib/recon/passiveRecon.js";
import { saveReport } from "./_lib/reports.js";

const scanSchema = z.object({
  url: z
    .string()
    .trim()
    .min(3, "URL is required")
    .transform((value) => normalizeUrl(value))
    .refine((value) => {
      try {
        const parsed = new URL(value);
        return ["http:", "https:"].includes(parsed.protocol) && parsed.hostname.includes(".");
      } catch {
        return false;
      }
    }, "Enter a valid HTTP or HTTPS URL"),
});

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return methodNotAllowed(res, ["POST"]);
  }

  const parsed = scanSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return sendJson(res, 400, {
      error: parsed.error.issues[0]?.message || "Invalid scan request",
    });
  }

  try {
    const report = makeReport(parsed.data.url);
    const recon = await runPassiveRecon(parsed.data.url);
    const enrichedReport = enrichReportWithRecon(report, recon);
    enrichedReport.summary = makeSummary(enrichedReport);
    const result = await saveReport(enrichedReport);

    return sendJson(res, 201, {
      report: result.report,
      meta: persistenceMeta(result.persisted),
    });
  } catch (error) {
    const isBlockedTarget =
      error.message?.includes("Private network") ||
      error.message?.includes("Localhost") ||
      error.message?.includes("Only HTTP") ||
      error.message?.includes("Target did not resolve") ||
      error.message?.includes("private network address");

    return sendJson(res, isBlockedTarget ? 400 : 500, {
      error: isBlockedTarget ? error.message : "Unable to create scan report",
      detail: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
}
