export function sendJson(res, status, payload) {
  res.status(status).json(payload);
}

export function methodNotAllowed(res, allowed) {
  res.setHeader("Allow", allowed);
  sendJson(res, 405, { error: "Method not allowed" });
}

export function persistenceMeta(enabled) {
  return {
    persistence: enabled ? "mongodb" : "memory",
  };
}
