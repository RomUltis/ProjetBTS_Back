const express = require("express");
const { ZONES } = require("../../config/maps");

/*
 * Routes alarme. L'armement/désarmement est désormais RELAYÉ à l'application
 * C++ (via alarm.arm()/disarm() → SurveillanceClient). Le back ne pilote plus
 * aucune sirène ; il conserve seulement les préférences (zones, sorties
 * exclues, durée sirène) à titre informatif pour le dashboard.
 */
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
        cpp_reachable: alarm.surveillance.isReachable(),
      });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // Ancienne route conservée pour compatibilité
  router.get("/alarm/status", requireAuth, async (req, res) => {
    res.json({ armed: alarm.isArmed() });
  });

  router.post("/api/alarm/arm", requireAuth, requireAdmin, async (req, res) => {
    try {
      const config = await alarm.loadConfig();
      const { armed, zones, excluded_do, siren_duration, beep } = req.body;

      if (typeof beep === "boolean") alarm.beepEnabled = beep;

      if (Array.isArray(zones)) config.armed_zones = zones.filter((z) => ZONES[z]);
      if (Array.isArray(excluded_do)) config.excluded_do = [...new Set(excluded_do.map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n <= 7))];
      if (typeof siren_duration === "number" && siren_duration > 0) config.siren_duration = Math.min(600, siren_duration);

      // Persiste les préférences (informatives côté back)
      await alarm.saveConfig(config);

      if (typeof armed !== "boolean") {
        // Appel "préférences seules" (ex : bascule des bips)
        return res.json({ ok: true, config });
      }

      // Action manuelle : l'horaire ne doit plus interférer
      alarm.armedBySchedule = false;
      const wasArmed = alarm.isArmed();

      if (armed) {
        // Refus local immédiat si une ouverture est ouverte (règle alignée sur le C++)
        const openDoors = alarm.openDoors();
        if (openDoors.length > 0 && !alarm.isArmed()) {
          const names = openDoors.map((d) => d.label).join(", ");
          return res.status(400).json({
            ok: false,
            error: `Impossible d'armer : porte(s)/fenêtre(s) ouverte(s) → ${names}`,
            open_doors: openDoors.map((d) => ({ ch: d.ch, label: d.label, zone: d.zone })),
          });
        }

        const result = await alarm.arm();
        if (!result.armed) {
          return res.status(409).json({
            ok: false,
            error: "Armement refusé par la centrale C++ (capteur ouvert ou état incompatible)",
          });
        }
        if (!wasArmed) alarm.beepArm().catch(() => {}); // double bip à l'armement (tâche de fond)
      } else {
        await alarm.disarm();
        if (wasArmed) alarm.beepDisarm().catch(() => {}); // simple bip au désarmement
      }

      res.json({ ok: true, config: { ...config, armed: alarm.isArmed() } });
    } catch (e) {
      res.status(502).json({ ok: false, error: `Centrale C++ injoignable : ${e.message}` });
    }
  });

  // Ancienne route de bascule
  router.post("/alarm/toggle", requireAuth, requireAdmin, async (req, res) => {
    try {
      const desired = !!req.body.armed;
      alarm.armedBySchedule = false;
      const wasArmed = alarm.isArmed();

      if (desired) {
        const openDoors = alarm.openDoors();
        if (openDoors.length > 0 && !alarm.isArmed()) {
          const names = openDoors.map((d) => d.label).join(", ");
          return res.status(400).json({
            ok: false,
            error: `Impossible d'armer : porte(s)/fenêtre(s) ouverte(s) → ${names}`,
          });
        }
        const result = await alarm.arm();
        if (!result.armed) {
          return res.status(409).json({ ok: false, error: "Armement refusé par la centrale C++" });
        }
        if (!wasArmed) alarm.beepArm().catch(() => {});
      } else {
        await alarm.disarm();
        if (wasArmed) alarm.beepDisarm().catch(() => {});
      }

      res.json({ ok: true, armed: alarm.isArmed() });
    } catch (e) {
      res.status(502).json({ ok: false, error: `Centrale C++ injoignable : ${e.message}` });
    }
  });

  router.post("/api/alarm/disarm", requireAuth, requireAdmin, async (req, res) => {
    try {
      alarm.armedBySchedule = false;
      const wasArmed = alarm.isArmed();
      await alarm.disarm();
      if (wasArmed) alarm.beepDisarm().catch(() => {});
      res.json({ ok: true, msg: "Désarmement relayé à la centrale C++" });
    } catch (e) {
      res.status(502).json({ ok: false, error: `Centrale C++ injoignable : ${e.message}` });
    }
  });

  return router;
};
