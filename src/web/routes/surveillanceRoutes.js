const express = require("express");

/*
 * Webhook appelé par l'application C++ : « le C++ dit au back d'enregistrer ».
 *
 * Sur intrusion, le C++ POST ici → le back démarre l'enregistrement de la
 * caméra d'alarme et le maintient jusqu'à une désactivation manuelle (le stop
 * effectif est piloté par le désarmement, cf. App.js / armedChange).
 *
 * Pas de JWT (appel machine-à-machine en LAN, comme /api/rfid/check) ; un
 * jeton partagé optionnel (SURVEILLANCE_TOKEN) peut être exigé via l'en-tête
 * x-surveillance-token.
 */
module.exports = function surveillanceRoutes({ recordings, cameras, config }) {
  const router = express.Router();

  function tokenOk(req, res) {
    const expected = config.surveillance.token;
    if (!expected) return true;
    if (req.headers["x-surveillance-token"] !== expected) {
      res.status(401).json({ ok: false, error: "token invalide" });
      return false;
    }
    return true;
  }

  router.post("/api/surveillance/event", (req, res) => {
    if (!tokenOk(req, res)) return;

    const { event, source } = req.body || {};

    switch (event) {
      case "intrusion":
      case "alarm_started":
      case "record_start": {
        const res2 = recordings.startAll("alarm");
        const ok = res2.filter((r) => r.ok).length;
        console.log(`[C++→REC] ${event}${source ? " (" + source + ")" : ""} → enregistrement sur ${ok}/${res2.length} caméra(s)`);
        return res.json({ ok: true, recordings: res2 });
      }

      case "disarmed":
      case "alarm_cleared":
      case "record_stop": {
        const stopped = recordings.stopAll({ onlyAuto: true });
        console.log(`[C++→REC] ${event} → ${stopped.length} enregistrement(s) arrêté(s)`);
        return res.json({ ok: true, stopped });
      }

      default:
        return res.status(400).json({ ok: false, error: "event inconnu" });
    }
  });

  return router;
};
