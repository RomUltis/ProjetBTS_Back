const express = require("express");
const path = require("path");

module.exports = function camRoutes({ cameras, hls, recordings, alarm, config, requireAuth, requireAuthFlexible, requireAdmin }) {
  const router = express.Router();

  // Flux HLS sécurisés (JWT flexible + RGPD + anti path-traversal)
  router.get("/cam/*", requireAuthFlexible, (req, res) => {
    if (config.rgpdCamsOnlyWhenArmed && !alarm.isArmed()) {
      return res.status(403).json({
        ok: false,
        error: "rgpd_disabled",
        message: "Caméras désactivées conformément au RGPD (art. 5.1.c). Activation lors de l'armement de l'alarme.",
      });
    }

    const relativePath = req.path.slice("/cam/".length);

    if (relativePath.includes("..") || relativePath.startsWith("/")) {
      return res.status(400).json({ ok: false, error: "Chemin invalide" });
    }

    const filepath = path.join(config.hls.outputPath, relativePath);
    const resolved = path.resolve(filepath);
    if (!resolved.startsWith(path.resolve(config.hls.outputPath))) {
      return res.status(400).json({ ok: false, error: "Chemin invalide" });
    }

    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    res.setHeader("Pragma", "no-cache");

    if (filepath.endsWith(".m3u8")) {
      res.setHeader("Content-Type", "application/vnd.apple.mpegurl");
    } else if (filepath.endsWith(".ts")) {
      res.setHeader("Content-Type", "video/mp2t");
    } else if (filepath.endsWith(".m4s") || filepath.endsWith(".mp4")) {
      res.setHeader("Content-Type", "video/mp4");
    }

    res.sendFile(filepath, (err) => {
      if (err && !res.headersSent) {
        res.status(404).json({ ok: false, error: "Fichier introuvable" });
      }
    });
  });

  router.get("/api/cam/list", requireAuth, (req, res) => {
    res.json({ ok: true, cameras: cameras.publicList(), alarm_rec_cam: cameras.alarmRecCam });
  });

  router.post("/api/cam/record/start", requireAuth, requireAdmin, (req, res) => {
    const camId = (req.body && req.body.cam_id) || cameras.alarmRecCam;
    const result = recordings.start("manual", camId);
    if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
    res.json(result);
  });

  router.post("/api/cam/record/stop", requireAuth, requireAdmin, (req, res) => {
    const camId = (req.body && req.body.cam_id) || cameras.alarmRecCam;
    const result = recordings.stop(camId);
    if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
    res.json(result);
  });

  router.get("/api/cam/record/status", requireAuth, (req, res) => {
    res.json(recordings.status());
  });

  router.get("/api/cam/recordings", requireAuth, (req, res) => {
    try {
      res.json({ ok: true, files: recordings.listFiles() });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.get("/api/cam/hls/status", requireAuth, requireAdmin, (req, res) => {
    res.json({ ok: true, enabled: config.hls.enable, streams: hls.statusList() });
  });

  router.post("/api/cam/hls/restart", requireAuth, requireAdmin, (req, res) => {
    const camId = req.body && req.body.cam_id;
    const quality = (req.body && req.body.quality) || "sub";
    const result = hls.restart(camId, quality);
    if (!result.ok) return res.status(400).json(result);
    res.json(result);
  });

  return router;
};
