import { z } from "zod";
import { methodNotAllowed, persistenceMeta, sendJson } from "../_lib/http.js";
import { listReports } from "../_lib/reports.js";

const querySchema = z.object({
  severity: z.enum(["all", "low", "medium", "high", "critical"]).optional().default("all"),
  search: z.string().trim().optional().default(""),
  page: z.coerce.number().int().positive().optional().default(1),
});

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return methodNotAllowed(res, ["GET"]);
  }

  const parsed = querySchema.safeParse(req.query || {});
  if (!parsed.success) {
    return sendJson(res, 400, { error: "Invalid report query" });
  }

  try {
    const result = await listReports({
      severity: parsed.data.severity,
      search: parsed.data.search,
      page: parsed.data.page,
      pageSize: 20,
    });

    return sendJson(res, 200, {
      reports: result.reports,
      total: result.total,
      page: result.page,
      pageSize: result.pageSize,
      meta: persistenceMeta(result.persisted),
    });
  } catch (error) {
    return sendJson(res, 500, {
      error: "Unable to load reports",
      detail: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
}
