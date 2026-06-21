import fs from "node:fs/promises";
import path from "node:path";
import { ESLint } from "eslint";
import { HtmlValidate } from "html-validate";
import { check as checkLinks } from "linkinator";
import pa11y from "pa11y";
import * as prettier from "prettier";
import { z } from "zod";
import { methodNotAllowed, sendJson } from "../_lib/http.js";

export const config = {
  maxDuration: 60,
};

const outputLimit = 12_000;
const projectRoot = process.cwd();
const excludedDirs = new Set([".git", ".vercel", "dist", "node_modules", "output"]);
const prettierExtensions = new Set([".css", ".html", ".js", ".json", ".jsx", ".md"]);
const tools = {
  lint: {
    label: "ESLint",
    command: "npm run analyze:lint",
    run: runLint,
  },
  format: {
    label: "Prettier",
    command: "npm run analyze:format",
    run: runFormat,
  },
  html: {
    label: "HTML Validate",
    command: "npm run analyze:html",
    run: runHtmlValidate,
  },
  a11y: {
    label: "Pa11y",
    command: "npm run analyze:a11y",
    run: runPa11y,
  },
  links: {
    label: "Linkinator",
    command: "npm run analyze:links",
    run: runLinkinator,
  },
};

const runToolSchema = z.object({
  toolId: z.enum(Object.keys(tools)),
});

function trimOutput(value = "") {
  const text = String(value).trim();
  return text.length > outputLimit ? `${text.slice(0, outputLimit)}\n...output truncated...` : text;
}

function result(ok, stdout, stderr = "", code = ok ? 0 : 1) {
  return {
    ok,
    code,
    stdout: trimOutput(stdout),
    stderr: trimOutput(stderr),
  };
}

function displayPath(filePath) {
  return path.relative(projectRoot, filePath) || filePath;
}

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function collectFiles(dir, predicate, files = []) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  await Promise.all(
    entries.map(async (entry) => {
      if (excludedDirs.has(entry.name)) return;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await collectFiles(fullPath, predicate, files);
      } else if (predicate(fullPath)) {
        files.push(fullPath);
      }
    }),
  );
  return files;
}

function getOrigin(req) {
  const protocol = req.headers["x-forwarded-proto"] || (req.headers.host?.startsWith("localhost") ? "http" : "https");
  return `${protocol}://${req.headers.host}`;
}

async function runLint() {
  const eslint = new ESLint({ cwd: projectRoot });
  const results = await eslint.lintFiles(["src/**/*.{js,jsx}", "api/**/*.js", "*.js"]);
  const errorCount = results.reduce((total, item) => total + item.errorCount, 0);
  const warningCount = results.reduce((total, item) => total + item.warningCount, 0);
  const formatter = await eslint.loadFormatter("stylish");
  const formatted = await formatter.format(results);

  return result(
    errorCount === 0,
    formatted || `ESLint checked ${results.length} files. No issues found.`,
    warningCount ? `${warningCount} warning${warningCount === 1 ? "" : "s"} found.` : "",
  );
}

async function runFormat() {
  const files = await collectFiles(projectRoot, (filePath) => prettierExtensions.has(path.extname(filePath)));
  const failures = [];

  await Promise.all(
    files.map(async (filePath) => {
      const source = await fs.readFile(filePath, "utf8");
      const config = (await prettier.resolveConfig(filePath)) || {};
      const isFormatted = await prettier.check(source, { ...config, filepath: filePath });
      if (!isFormatted) failures.push(displayPath(filePath));
    }),
  );

  return result(
    failures.length === 0,
    failures.length
      ? `Prettier found formatting drift in:\n${failures.sort().join("\n")}`
      : `Prettier checked ${files.length} files. All matched files use Prettier code style.`,
  );
}

async function runHtmlValidate() {
  const configPath = path.join(projectRoot, ".htmlvalidate.json");
  const htmlConfig = (await pathExists(configPath)) ? JSON.parse(await fs.readFile(configPath, "utf8")) : undefined;
  const htmlvalidate = new HtmlValidate(htmlConfig);
  const report = await htmlvalidate.validateFile(path.join(projectRoot, "index.html"));
  const messages = report.results.flatMap((item) =>
    item.messages.map(
      (message) => `${displayPath(item.filePath)}:${message.line}:${message.column} ${message.message}`,
    ),
  );

  return result(
    report.valid,
    report.valid ? "HTML Validate checked index.html. No issues found." : messages.join("\n"),
  );
}

async function runPa11y(req) {
  const url = getOrigin(req);
  const report = await pa11y(url, {
    standard: "WCAG2AA",
    timeout: 30_000,
    chromeLaunchConfig: {
      args: ["--no-sandbox"],
    },
  });
  const errors = report.issues.filter((issue) => issue.type === "error");
  const lines = report.issues.map((issue) => `${issue.type.toUpperCase()}: ${issue.message}\n${issue.selector}`);

  return result(
    errors.length === 0,
    lines.length ? lines.join("\n\n") : `Pa11y checked ${url}. No WCAG2AA issues found.`,
  );
}

async function runLinkinator(req) {
  const url = getOrigin(req);
  const response = await checkLinks({
    path: url,
    recurse: true,
    concurrency: 2,
  });
  const broken = response.links.filter((link) => link.state !== "OK");
  const lines = response.links.map((link) => `[${link.status || link.state}] ${link.url}`);

  return result(
    broken.length === 0,
    lines.join("\n") || `Linkinator checked ${url}. No links found.`,
    broken.length ? `${broken.length} broken link${broken.length === 1 ? "" : "s"} found.` : "",
  );
}

async function runTool(tool, req) {
  try {
    return await tool.run(req);
  } catch (error) {
    return result(false, "", error.message || "Unable to run this analysis tool.");
  }
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return methodNotAllowed(res, ["POST"]);
  }

  const parsed = runToolSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return sendJson(res, 400, { error: "Unsupported analysis tool" });
  }

  const tool = tools[parsed.data.toolId];
  const startedAt = new Date();
  const runResult = await runTool(tool, req);

  return sendJson(res, 200, {
    tool: {
      id: parsed.data.toolId,
      name: tool.label,
      command: tool.command,
    },
    result: runResult,
    meta: {
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
    },
  });
}
