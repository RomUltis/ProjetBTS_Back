function makeAuthMiddleware(authService) {
  function requireAuth(req, res, next) {
    const auth = req.headers.authorization || "";
    const parts = auth.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return res.status(401).json({ ok: false, error: "Token manquant" });
    }
    try {
      req.user = authService.verify(parts[1]);
      return next();
    } catch {
      return res.status(401).json({ ok: false, error: "Token invalide" });
    }
  }

  // Flux HLS : token accepté via header Bearer, query ?token= ou cookie
  function requireAuthFlexible(req, res, next) {
    let token = null;

    const authHeader = req.headers.authorization || "";
    const parts = authHeader.split(" ");
    if (parts.length === 2 && parts[0] === "Bearer") {
      token = parts[1];
    }

    if (!token && req.query && req.query.token) {
      token = req.query.token;
    }

    if (!token && req.headers.cookie) {
      const match = req.headers.cookie.match(/(?:^|; )alarme_token=([^;]+)/);
      if (match) token = decodeURIComponent(match[1]);
    }

    if (!token) {
      return res.status(401).json({ ok: false, error: "Token manquant" });
    }
    try {
      req.user = authService.verify(token);
      return next();
    } catch {
      return res.status(401).json({ ok: false, error: "Token invalide" });
    }
  }

  function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
      return res.status(403).json({ ok: false, error: "Accès réservé aux administrateurs" });
    }
    return next();
  }

  return { requireAuth, requireAuthFlexible, requireAdmin };
}

module.exports = { makeAuthMiddleware };
