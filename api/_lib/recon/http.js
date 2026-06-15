import { assertSafePublicTarget, safeError } from "./safety.js";

const securityHeaderNames = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
];

export function evaluateHeaders(headers) {
  const normalized = {};
  for (const [key, value] of headers.entries()) {
    normalized[key.toLowerCase()] = value;
  }

  const checks = securityHeaderNames.map((name) => ({
    name,
    present: Boolean(normalized[name]),
    value: normalized[name] || "",
  }));

  return {
    checks,
    missing: checks.filter((check) => !check.present).map((check) => check.name),
    present: checks.filter((check) => check.present).map((check) => check.name),
  };
}

export async function collectHttpRecon(inputUrl) {
  const hops = [];
  let currentUrl = inputUrl;
  let finalHeaders = new Headers();
  let finalStatus = null;

  for (let index = 0; index < 6; index += 1) {
    await assertSafePublicTarget(currentUrl);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6500);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "user-agent": "VeilURLPassiveRecon/1.0",
          accept: "text/html,*/*;q=0.8",
        },
      });

      finalHeaders = response.headers;
      finalStatus = response.status;
      const location = response.headers.get("location");
      hops.push({
        url: currentUrl,
        status: response.status,
        location,
      });

      if (!location || response.status < 300 || response.status >= 400 || index === 5) {
        break;
      }

      currentUrl = new URL(location, currentUrl).toString();
    } catch (error) {
      hops.push({
        url: currentUrl,
        status: 0,
        error: safeError(error),
      });
      break;
    } finally {
      clearTimeout(timer);
    }
  }

  const startHost = new URL(inputUrl).hostname.replace(/^www\./, "");
  const finalUrl = hops.at(-1)?.url || inputUrl;
  const finalHost = new URL(finalUrl).hostname.replace(/^www\./, "");

  return {
    finalUrl,
    finalStatus,
    hops,
    hopCount: Math.max(0, hops.length - 1),
    crossDomain: startHost !== finalHost,
    upgradedToHttps: inputUrl.startsWith("http://") && finalUrl.startsWith("https://"),
    headers: evaluateHeaders(finalHeaders),
    server: finalHeaders.get("server") || "",
  };
}

export async function fetchSmallText(url) {
  const hops = [];
  let currentUrl = url;

  for (let index = 0; index < 4; index += 1) {
    await assertSafePublicTarget(currentUrl);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "user-agent": "VeilURLPassiveRecon/1.0",
          accept: "text/plain,*/*;q=0.5",
        },
      });
      const location = response.headers.get("location");
      hops.push({
        url: currentUrl,
        status: response.status,
        location,
      });

      if (location && response.status >= 300 && response.status < 400 && index < 3) {
        currentUrl = new URL(location, currentUrl).toString();
        continue;
      }

      const text = await response.text();
      return {
        found: response.ok,
        status: response.status,
        finalUrl: currentUrl,
        hops,
        text: text.slice(0, 8000),
      };
    } catch (error) {
      return {
        found: false,
        status: 0,
        finalUrl: currentUrl,
        hops,
        error: safeError(error),
        text: "",
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    found: false,
    status: 0,
    finalUrl: currentUrl,
    hops,
    error: "Well-known fetch exceeded redirect limit",
    text: "",
  };
}
