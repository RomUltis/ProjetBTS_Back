const express = require("express");
const { ZONES } = require("../../config/maps");

module.exports = function alarmRoutes({ alarm, requireAuth, requireAdmin }) {
  const router = express.Router();

  router.get("/api/alarm/status", requireAuth, async (req, res) => {
    try {
      const config = await alarm.loadConfig();
      res.json({
        ok: true,
        armed: config.armed,
        armed_zones: config.armed_zones,
        excluded_do: config.excluded_do,
        siren_duration: config.siren_duration,
        alarm_triggered: alarm.triggered,
        alarm_info: alarm.triggerInfo,
        armed_by_schedule: alarm.armedBySchedule,
        beep_enabled: alarm.beepEnabled,
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Ancienne route conservée pour compatibilité
  router.get("/alarm/status", requireAuth, async (req, res) => {
    try {
      const config = await alarm.loadConfig();
      res.json({ armed: config.armed });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.post("/api/alarm/arm", requireAuth, requireAdmin, async (req, res) => {
    try {
      const config = await alarm.loadConfig();
      const { armed, zones, excluded_do, siren_duration, beep } = req.body;

      if (typeof beep === "boolean") alarm.beepEnabled = beep;

      if (Array.isArray(zones)) config.armed_zones = zones.filter((z) => ZONES[z]);
      if (Array.isArray(excluded_do)) config.excluded_do = [...new Set(excluded_do.map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n <= 7))];
      if (typeof siren_duration === "number" && siren_duration > 0) config.siren_duration = Math.min(600, siren_duration);

      // Avant d'armer : refuser si une porte/fenêtre d'une zone armée est ouverte
      if (armed === true && !config.armed) {
        const openDoors = alarm.findOpenDoors(config.armed_zones);
        if (openDoors.length > 0) {
          const names = openDoors.map((d) => d.label).join(", ");
          return res.status(400).json({
            ok: false,
            error: `Impossible d'armer : porte(s)/fenêtre(s) ouverte(s) → ${names}`,
            open_doors: openDoors.map((d) => ({ ch: d.ch, label: d.label, zone: d.zone })),
          });
        }
      }

      const wasArmed = config.armed;

      if (typeof armed === "boolean") config.armed = armed;
      // Action manuelle : l'horaire ne doit plus interférer
      if (typeof armed === "boolean") alarm.armedBySchedule = false;

      await alarm.saveConfig(config);

      // Double bip seulement au passage désarmé -> armé
      if (config.armed && !wasArmed && alarm.beepEnabled) {
        await alarm.beepArm();
        console.log(`🔔🔔 Double bip armement (dashboard)`);
      }

      // Bip simple seulement au passage armé -> désarmé
      if (!config.armed && wasArmed && alarm.beepEnabled) {
        await alarm.beepDisarm();
        console.log(`🔔 Bip désarmement (dashboard)`);
      }

      if (!config.armed && alarm.triggered) {
        await alarm.disarm();
      }
      if (!config.armed) {
        alarm.triggered = false;
        alarm.triggerInfo = null;
      }

      res.json({ ok: true, config });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Ancienne route de bascule
  router.post("/alarm/toggle", requireAuth, requireAdmin, async (req, res) => {
    try {
      const config = await alarm.loadConfig();
      const desired = !!req.body.armed;

      if (desired && !config.armed) {
        const openDoors = alarm.findOpenDoors(config.armed_zones);
        if (openDoors.length > 0) {
          const names = openDoors.map((d) => d.label).join(", ");
          return res.status(400).json({
            ok: false,
            error: `Impossible d'armer : porte(s)/fenêtre(s) ouverte(s) → ${names}`,
          });
        }
      }

      config.armed = desired;
      alarm.armedBySchedule = false;
      await alarm.saveConfig(config);

      if (!config.armed && alarm.triggered) {
        await alarm.disarm();
      }
      if (!config.armed) {
        alarm.triggered = false;
        alarm.triggerInfo = null;
      }

      res.json({ ok: true, armed: config.armed });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.post("/api/alarm/disarm", requireAuth, requireAdmin, async (req, res) => {
    try {
      const config = await alarm.loadConfig();
      config.armed = false;
      alarm.armedBySchedule = false;
      await alarm.saveConfig(config);
      await alarm.disarm();
      res.json({ ok: true, msg: "Désarmé, tous les DO coupés" });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  return router;
};
