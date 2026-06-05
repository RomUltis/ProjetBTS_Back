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
    const camId = cameras.alarmRecCam;

    switch (event) {
      case "intrusion":
      case "alarm_started":
      case "record_start": {
        const r = recordings.start("alarm", camId);
        console.log(`[C++→REC] ${event}${source ? " (" + source + ")" : ""} → enregistrement ${r.ok ? "démarré" : "(" + r.reason + ")"}`);
        return res.json({ ok: true, recording: r });
      }

      case "disarmed":
      case "alarm_cleared":
      case "record_stop": {
        const cur = recordings.get(camId);
        if (cur && cur.autoAlarm) {
          const r = recordings.stop(camId);
          console.log(`[C++→REC] ${event} → enregistrement arrêté`);
          return res.json({ ok: true, recording: r });
        }
        return res.json({ ok: true, recording: { ok: false, reason: "not_auto_recording" } });
      }

      default:
        return res.status(400).json({ ok: false, error: "event inconnu" });
    }
  });

  return router;
};
