import mongoose from "mongoose";

const scoreBreakdownSchema = new mongoose.Schema(
  {
    domain: Number,
    security: Number,
    reputation: Number,
    content: Number,
  },
  { _id: false },
);

const scanReportSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    inputUrl: { type: String, required: true },
    url: { type: String, required: true },
    normalizedUrl: { type: String, required: true },
    domain: { type: String, required: true, index: true },
    score: { type: Number, required: true },
    riskScore: { type: Number, required: true },
    threatScore: Number,
    postureScore: Number,
    level: { type: String, enum: ["low", "medium", "high", "critical"], required: true, index: true },
    riskLevel: { type: String, enum: ["low", "medium", "high", "critical"], required: true },
    status: { type: String, enum: ["pass", "warn", "fail"], required: true },
    verdict: { type: String, required: true },
    summary: String,
    scannedAt: String,
    ip: String,
    server: String,
    responseMs: Number,
    registeredDays: Number,
    expiresDays: Number,
    keywordHits: [String],
    redirectCount: Number,
    reputationHits: Number,
    headerMisses: Number,
    tld: String,
    scoreBreakdown: scoreBreakdownSchema,
    recon: mongoose.Schema.Types.Mixed,
  },
  { timestamps: true },
);

export default mongoose.models.ScanReport || mongoose.model("ScanReport", scanReportSchema);
