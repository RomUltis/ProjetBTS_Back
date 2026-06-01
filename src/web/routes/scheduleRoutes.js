const express = require("express");

module.exports = function scheduleRoutes({ scheduleService, db, requireAuth, requireAdmin }) {
  const router = express.Router();

  router.get("/schedule", requireAuth, async (req, res) => {
    try {
      const slots = await scheduleService.loadSlots();
      res.json({ slots });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Remplace toutes les plages
  router.put("/schedule", requireAuth, requireAdmin, async (req, res) => {
    try {
      const slots = Array.isArray(req.body?.slots) ? req.body.slots : [];
      await db.query("DELETE FROM `schedule_slots`");
      for (const s of slots) {
        if (s.start && s.end) {
          await db.query("INSERT INTO `schedule_slots` (`start`, `end`) VALUES (?, ?)", [s.start, s.end]);
        }
      }
      res.json({ ok: true, slots });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Utilisé par le serveur C++
  router.get("/api/schedule/now", async (req, res) => {
    try {
      const r = await scheduleService.now();
      return res.json({ ok: true, ...r });
    } catch (e) {
      console.error("[API C++] /api/schedule/now error:", e.message);
      return res.status(500).json({ ok: false, error: e.message });
    }
  });

  return router;
};
