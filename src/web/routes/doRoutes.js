const express = require("express");

module.exports = function doRoutes({ petDO, config, requireAuth, requireAdmin }) {
  const router = express.Router();

  router.post("/api/pet/do/pulse", requireAuth, requireAdmin, async (req, res) => {
    try {
      const channel = Number(req.body?.channel);
      const ms = config.clampPulseMs(req.body?.ms ?? config.PULSE_MS_DEFAULT);
      if (!Number.isInteger(channel) || channel < 0 || channel > 7) {
        return res.status(400).json({ ok: false, error: "channel must be 0..7" });
      }
      await petDO.pulseCoil(channel, ms);
      return res.json({ ok: true, channel, ms });
    } catch (e) {
      return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
  });

  router.post("/api/pet/do/test-all", requireAuth, requireAdmin, async (req, res) => {
    try {
      const ms = config.clampPulseMs(req.body?.ms ?? config.PULSE_MS_DEFAULT);
      const delay = Math.min(5000, Math.max(200, Number(req.body?.delay ?? config.TEST_DELAY_DEFAULT)));
      (async () => {
        for (let ch = 0; ch <= 7; ch++) {
          try { await petDO.pulseCoil(ch, ms); }
          catch (e) { console.error(`Test DO${ch} failed:`, e?.message || e); }
          await new Promise((r) => setTimeout(r, delay));
        }
      })();
      return res.json({ ok: true, action: "test_all", ms, delay });
    } catch (e) {
      return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
  });

  router.post("/api/pet/do/test-selected", requireAuth, requireAdmin, async (req, res) => {
    try {
      const ms = config.clampPulseMs(req.body?.ms ?? config.PULSE_MS_DEFAULT);
      const delay = Math.min(5000, Math.max(200, Number(req.body?.delay ?? config.TEST_DELAY_DEFAULT)));
      const channels = Array.isArray(req.body?.channels) ? req.body.channels : [];
      const clean = [...new Set(channels.map(Number))].filter((n) => Number.isInteger(n) && n >= 0 && n <= 7);
      if (clean.length === 0) return res.status(400).json({ ok: false, error: "Aucun relais sélectionné" });

      (async () => {
        for (const ch of clean) {
          try { await petDO.pulseCoil(ch, ms); }
          catch (e) { console.error(`Test DO${ch} failed:`, e?.message || e); }
          await new Promise((r) => setTimeout(r, delay));
        }
      })();

      return res.json({ ok: true, action: "test_selected", channels: clean, ms, delay });
    } catch (e) {
      return res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
  });

  return router;
};
