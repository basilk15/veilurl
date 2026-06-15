import { methodNotAllowed, persistenceMeta, sendJson } from "../_lib/http.js";
import { deleteReportById, getReportById } from "../_lib/reports.js";

export default async function handler(req, res) {
  const { id } = req.query;

  if (!id) {
    return sendJson(res, 400, { error: "Report ID is required" });
  }

  if (req.method === "GET") {
    try {
      const report = await getReportById(id);
      if (!report) return sendJson(res, 404, { error: "Report not found" });

      return sendJson(res, 200, {
        report,
        meta: persistenceMeta(Boolean(process.env.MONGODB_URI)),
      });
    } catch (error) {
      return sendJson(res, 500, {
        error: "Unable to load report",
        detail: process.env.NODE_ENV === "development" ? error.message : undefined,
      });
    }
  }

  if (req.method === "DELETE") {
    try {
      const result = await deleteReportById(id);
      return sendJson(res, 200, {
        deleted: result.deleted,
        meta: persistenceMeta(result.persisted),
      });
    } catch (error) {
      return sendJson(res, 500, {
        error: "Unable to delete report",
        detail: process.env.NODE_ENV === "development" ? error.message : undefined,
      });
    }
  }

  return methodNotAllowed(res, ["GET", "DELETE"]);
}
