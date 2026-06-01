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

  return router;
};
