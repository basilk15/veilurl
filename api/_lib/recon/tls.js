import tls from "node:tls";

export async function collectTlsRecon(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: 5500,
    });

    function finish(payload) {
      socket.destroy();
      resolve(payload);
    }

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate(true);
      const validToTime = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
      const validFromTime = cert.valid_from ? Date.parse(cert.valid_from) : NaN;
      const daysRemaining = Number.isFinite(validToTime)
        ? Math.ceil((validToTime - Date.now()) / (1000 * 60 * 60 * 24))
        : null;
      const san = typeof cert.subjectaltname === "string"
        ? cert.subjectaltname.split(",").map((item) => item.trim().replace(/^DNS:/, "")).slice(0, 12)
        : [];

      finish({
        available: true,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || "",
        issuer: cert.issuer?.O || cert.issuer?.CN || "",
        subject: cert.subject?.CN || "",
        validFrom: Number.isFinite(validFromTime) ? new Date(validFromTime).toISOString() : "",
        validTo: Number.isFinite(validToTime) ? new Date(validToTime).toISOString() : "",
        daysRemaining,
        san,
        expired: typeof daysRemaining === "number" ? daysRemaining < 0 : false,
        expiringSoon: typeof daysRemaining === "number" ? daysRemaining >= 0 && daysRemaining <= 14 : false,
      });
    });

    socket.once("timeout", () => finish({ available: false, error: "TLS connection timed out" }));
    socket.once("error", (error) => finish({ available: false, error: error.message }));
  });
}
