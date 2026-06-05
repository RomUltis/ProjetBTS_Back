const express = require("express");

module.exports = function rfidRoutes({ rfid, requireAuth, requireAdmin }) {
  const router = express.Router();

  // Vérification appelée par le serveur C++
  router.get("/api/rfid/check/:uid", async (req, res) => {
    try {
      const uid = rfid.normalizeUid(req.params.uid);
      if (!uid) {
        return res.status(400).json({ ok: false, authorized: false, error: "UID manquant" });
      }
      const result = await rfid.check(uid, { log: true });
      return res.json(result);
    } catch (e) {
      console.error("[API C++] /api/rfid/check error:", e.message);
      return res.status(500).json({ ok: false, authorized: false, error: e.message });
    }
  });

  router.post("/api/rfid/check", async (req, res) => {
    try {
      const uid = rfid.normalizeUid(req.body?.uid || req.body?.card_id);
      if (!uid) {
        return res.status(400).json({ ok: false, authorized: false, error: "UID manquant" });
      }
      const result = await rfid.check(uid);
      return res.json(result);
    } catch (e) {
      console.error("[API C++] POST /api/rfid/check error:", e.message);
      return res.status(500).json({ ok: false, authorized: false, error: e.message });
    }
  });

  // Gestion des badges
  router.get("/rfid", requireAuth, async (req, res) => {
    try {
      const badges = await rfid.listBadges();
      res.json({ badges });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.post("/rfid", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { uid, owner, enabled } = req.body || {};
      if (!uid) return res.status(400).json({ ok: false, error: "UID requis" });
      await rfid.addBadge({ uid, owner, enabled });
      res.json({ ok: true, message: "Badge ajouté" });
    } catch (e) {
      if (e.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ ok: false, error: "Ce badge existe déjà" });
      }
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.patch("/rfid/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { enabled } = req.body || {};
      await rfid.toggleBadge(req.params.id, enabled);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.delete("/rfid/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      await rfid.removeBadge(req.params.id);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // NB : le scan matériel n'est plus reçu ici. L'app C++ reçoit les badges de
  // l'Arduino et interroge /api/rfid/check ci-dessus ; c'est elle qui pilote
  // l'armement/désarmement et la gâche.

  // Enrollment (détection automatique d'un badge)
  router.post("/rfid/enroll/start", requireAuth, requireAdmin, (req, res) => {
    res.json(rfid.enrollStart());
  });

  router.get("/rfid/enroll/status", requireAuth, (req, res) => {
    res.json(rfid.enrollStatus());
  });

  router.post("/rfid/enroll/stop", requireAuth, requireAdmin, (req, res) => {
    res.json(rfid.enrollStop());
  });

  return router;
};
