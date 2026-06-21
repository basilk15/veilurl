import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";
import { methodNotAllowed, sendJson } from "../_lib/http.js";

const execFileAsync = promisify(execFile);
const outputLimit = 12_000;
const ansiPattern = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");
const tools = {
  lint: {
    label: "ESLint",
    script: "analyze:lint",
  },
  format: {
    label: "Prettier",
    script: "analyze:format",
  },
  html: {
    label: "HTML Validate",
    script: "analyze:html",
  },
  a11y: {
    label: "Pa11y",
    script: "analyze:a11y",
  },
  links: {
    label: "Linkinator",
    script: "analyze:links",
  },
};

const runToolSchema = z.object({
  toolId: z.enum(Object.keys(tools)),
});

function cleanOutput(value = "") {
  const text = String(value).replace(ansiPattern, "").trim();
  return text.length > outputLimit ? `${text.slice(0, outputLimit)}\n...output truncated...` : text;
}

async function runScript(script) {
  try {
    const result = await execFileAsync("npm", ["run", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        CI: "1",
        FORCE_COLOR: "0",
        NO_COLOR: "1",
      },
      timeout: 120_000,
      maxBuffer: 1024 * 1024 * 8,
    });

    return {
      ok: true,
      code: 0,
      stdout: cleanOutput(result.stdout),
      stderr: cleanOutput(result.stderr),
    };
  } catch (error) {
    return {
      ok: false,
      code: typeof error.code === "number" ? error.code : 1,
      signal: error.signal,
      timedOut: Boolean(error.killed && error.signal === "SIGTERM"),
      stdout: cleanOutput(error.stdout),
      stderr: cleanOutput(error.stderr || error.message),
    };
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
  const result = await runScript(tool.script);

  return sendJson(res, 200, {
    tool: {
      id: parsed.data.toolId,
      name: tool.label,
      command: `npm run ${tool.script}`,
    },
    result,
    meta: {
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
    },
  });
}
