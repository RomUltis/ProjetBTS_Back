const express = require("express");
const { DI_MAP, DO_MAP, ZONES } = require("../../config/maps");

module.exports = function diRoutes({ diPoller, alarm, db, requireAuth }) {
  const router = express.Router();

  router.get("/api/di/status", requireAuth, async (req, res) => {
    try {
      res.json({
        ok: true,
        inputs: diPoller.currentStatus(),
        alarm_triggered: alarm.triggered,
        alarm_info: alarm.triggerInfo,
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Lecture forcée (rafraîchissement à la demande)
  router.get("/api/di/read", requireAuth, async (req, res) => {
    try {
      const inputs = await diPoller.readMapped();
      res.json({ ok: true, inputs });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Historique (?limit=50&channel=4&triggered=1&zone=)
  router.get("/api/di/events", requireAuth, async (req, res) => {
    try {
      let sql = "SELECT * FROM di_events";
      const conditions = [];
      const params = [];

      if (req.query.channel !== undefined) {
        conditions.push("channel = ?");
        params.push(Number(req.query.channel));
      }
      if (req.query.triggered !== undefined) {
        conditions.push("triggered = ?");
        params.push(Number(req.query.triggered));
      }
      if (req.query.zone) {
        conditions.push("zone LIKE ?");
        params.push(`%${req.query.zone}%`);
      }

      if (conditions.length) sql += " WHERE " + conditions.join(" AND ");
      sql += " ORDER BY created_at DESC";

      const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 100));
      sql += ` LIMIT ${limit}`;

      const rows = await db.query(sql, params);
      res.json({ ok: true, events: rows, count: rows.length });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.get("/api/di/mapping", requireAuth, (req, res) => {
    res.json({ ok: true, inputs: DI_MAP, outputs: DO_MAP, zones: ZONES });
  });

  // Réception d'un événement capteur depuis l'application C++ (E2)
  // Appelé uniquement quand le système est ARMÉ côté C++.
  // Pas d'auth JWT : appelé machine-to-machine en réseau local (même pattern que /api/surveillance/event).
  router.post("/api/di/event", async (req, res) => {
    try {
      const { channel, zone, label, value, triggered } = req.body;
      if (channel === undefined || channel === null) {
        return res.status(400).json({ ok: false, error: "channel manquant" });
      }
      await db.query(
        "INSERT INTO di_events (channel, zone, label, value, triggered) VALUES (?, ?, ?, ?, ?)",
        [
          Number(channel),
          zone   || null,
          label  || null,
          value     ? 1 : 0,
          triggered ? 1 : 0,
        ]
      );
      res.json({ ok: true });
    } catch (e) {
      console.error("POST /api/di/event error:", e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  return router;
};
