import { safeError } from "./safety.js";

function vcardValue(entity, fieldName) {
  const values = entity?.vcardArray?.[1] || [];
  const row = values.find((item) => item?.[0] === fieldName);
  return row?.[3] || "";
}

function eventDate(events, action) {
  return events?.find((event) => event.eventAction === action)?.eventDate || "";
}

function daysBetween(dateValue, now = Date.now()) {
  const time = Date.parse(dateValue);
  if (!Number.isFinite(time)) return null;
  return Math.round((now - time) / (1000 * 60 * 60 * 24));
}

function daysUntil(dateValue, now = Date.now()) {
  const time = Date.parse(dateValue);
  if (!Number.isFinite(time)) return null;
  return Math.ceil((time - now) / (1000 * 60 * 60 * 24));
}

export async function collectRdapRecon(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5500);

  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      headers: {
        "user-agent": "VeilURLPassiveRecon/1.0",
        accept: "application/rdap+json,application/json;q=0.9,*/*;q=0.2",
      },
    });

    if (!response.ok) {
      return {
        found: false,
        status: response.status,
        registrar: "",
        registeredAt: "",
        expiresAt: "",
        updatedAt: "",
        nameservers: [],
      };
    }

    const payload = await response.json();
    const registrarEntity = payload.entities?.find((entity) => entity.roles?.includes("registrar"));
    const registeredAt = eventDate(payload.events, "registration");
    const expiresAt = eventDate(payload.events, "expiration");

    return {
      found: true,
      status: response.status,
      registrar: vcardValue(registrarEntity, "fn") || payload.registrar || "",
      registeredAt,
      expiresAt,
      updatedAt: eventDate(payload.events, "last changed"),
      registeredDays: daysBetween(registeredAt),
      expiresDays: daysUntil(expiresAt),
      nameservers: (payload.nameservers || []).map((server) => server.ldhName).filter(Boolean).slice(0, 8),
      notices: (payload.notices || []).map((notice) => notice.title).filter(Boolean).slice(0, 4),
    };
  } catch (error) {
    return {
      found: false,
      status: 0,
      error: safeError(error),
      registrar: "",
      registeredAt: "",
      expiresAt: "",
      updatedAt: "",
      nameservers: [],
    };
  } finally {
    clearTimeout(timer);
  }
}
