import ScanReport from "./ScanReport.js";
import { connectToDatabase, hasMongoUri } from "./db.js";
import { makeSeedReports } from "../../src/lib/demoScanner.js";

export function serializeReport(report) {
  const source = typeof report.toObject === "function" ? report.toObject() : report;
  return {
    ...source,
    id: source.id,
    createdAt: source.createdAt ? new Date(source.createdAt).toISOString() : source.createdAt,
    updatedAt: source.updatedAt ? new Date(source.updatedAt).toISOString() : source.updatedAt,
  };
}

export async function saveReport(report) {
  if (!hasMongoUri()) {
    return { report, persisted: false };
  }

  await connectToDatabase();
  const saved = await ScanReport.findOneAndUpdate(
    { id: report.id },
    { $set: report },
    { returnDocument: "after", upsert: true, setDefaultsOnInsert: true }
  );

  return { report: serializeReport(saved), persisted: true };
}

export async function listReports({ severity, search, page = 1, pageSize = 20 }) {
  if (!hasMongoUri()) {
    let reports = makeSeedReports();
    if (severity && severity !== "all") reports = reports.filter((report) => report.level === severity);
    if (search) {
      const lower = search.toLowerCase();
      reports = reports.filter((report) => report.domain.toLowerCase().includes(lower) || report.id.toLowerCase().includes(lower));
    }
    return {
      reports,
      total: reports.length,
      page,
      pageSize,
      persisted: false,
    };
  }

  await connectToDatabase();
  const query = {};
  if (severity && severity !== "all") query.level = severity;
  if (search) {
    query.$or = [
      { domain: { $regex: search, $options: "i" } },
      { id: { $regex: search, $options: "i" } },
      { url: { $regex: search, $options: "i" } },
    ];
  }

  const skip = (page - 1) * pageSize;
  const [items, total] = await Promise.all([
    ScanReport.find(query).sort({ updatedAt: -1 }).skip(skip).limit(pageSize).lean(),
    ScanReport.countDocuments(query),
  ]);

  return {
    reports: items.map(serializeReport),
    total,
    page,
    pageSize,
    persisted: true,
  };
}

export async function getReportById(id) {
  if (!hasMongoUri()) {
    return makeSeedReports().find((report) => report.id === id) || null;
  }

  await connectToDatabase();
  const report = await ScanReport.findOne({ id }).lean();
  return report ? serializeReport(report) : null;
}

export async function deleteReportById(id) {
  if (!hasMongoUri()) {
    return { deleted: false, persisted: false };
  }

  await connectToDatabase();
  const result = await ScanReport.deleteOne({ id });
  return { deleted: result.deletedCount > 0, persisted: true };
}
