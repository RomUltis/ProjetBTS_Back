const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

// Un enregistrement FFmpeg par caméra (plusieurs caméras en parallèle possible).
class RecordingManager {
  constructor({ config, cameras }) {
    this.config = config;
    this.cameras = cameras;
    this.recordings = {};
  }

  get(camId) {
    return this.recordings[camId];
  }

  start(source = "manual", camId = this.cameras.alarmRecCam) {
    const cam = this.cameras.getCamById(camId);
    if (!cam) return { ok: false, reason: "unknown_cam" };
    if (this.recordings[camId]) return { ok: false, reason: "already_recording" };

    const rtspUrl = cam.rtsp_main || this.config.RTSP_URL;
    if (!rtspUrl) return { ok: false, reason: "no_rtsp_url" };

    try {
      if (!fs.existsSync(this.config.RECORDINGS_PATH)) {
        fs.mkdirSync(this.config.RECORDINGS_PATH, { recursive: true });
      }
    } catch (e) {
      console.error("[REC] Impossible de créer le dossier:", e.message);
      return { ok: false, reason: e.message };
    }

    const now = new Date();
    const ts = now.toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const prefix = source === "alarm" ? "alarme" : "rec";
    const filename = `${prefix}_${camId}_${ts}.mp4`;
    const filepath = path.join(this.config.RECORDINGS_PATH, filename);

    const proc = spawn("ffmpeg", [
      "-rtsp_transport", "tcp",
      "-i", rtspUrl,
      "-c:v", "copy",
      "-c:a", "aac",
      "-y",
      filepath,
    ]);

    const state = {
      process: proc,
      startTime: Date.now(),
      filename,
      autoAlarm: source === "alarm",
      camId,
    };
    this.recordings[camId] = state;

    proc.stderr.on("data", () => {});

    proc.on("error", (err) => {
      console.error(`[REC ${camId}] Erreur FFmpeg:`, err.message);
      delete this.recordings[camId];
    });

    proc.on("close", (code) => {
      console.log(`[REC ${camId}] FFmpeg terminé (code ${code}) — ${filename}`);
      delete this.recordings[camId];
    });

    console.log(`[REC ${camId}] ⏺ Enregistrement démarré (${source}) → ${filepath}`);
    return { ok: true, cam_id: camId, filename, path: filepath };
  }

  stop(camId = this.cameras.alarmRecCam) {
    const state = this.recordings[camId];
    if (!state) return { ok: false, reason: "not_recording" };

    const filename = state.filename;
    const duration = Math.round((Date.now() - state.startTime) / 1000);
    state.process.kill("SIGINT");

    console.log(`[REC ${camId}] ⏹ Enregistrement arrêté — ${filename} (${duration}s)`);
    return { ok: true, cam_id: camId, filename, duration_seconds: duration };
  }

  // Champs racine = caméra d'alarme par défaut (rétrocompat), détail dans by_cam
  status() {
    const byCam = {};
    for (const [camId, st] of Object.entries(this.recordings)) {
      byCam[camId] = {
        recording: true,
        filename: st.filename,
        elapsed_seconds: Math.round((Date.now() - st.startTime) / 1000),
        auto_alarm: st.autoAlarm,
      };
    }

    const defaultSt = this.recordings[this.cameras.alarmRecCam];
    if (!defaultSt) {
      return { ok: true, recording: false, by_cam: byCam };
    }

    const elapsed = Math.round((Date.now() - defaultSt.startTime) / 1000);
    return {
      ok: true,
      recording: true,
      filename: defaultSt.filename,
      elapsed_seconds: elapsed,
      auto_alarm: defaultSt.autoAlarm,
      by_cam: byCam,
    };
  }

  listFiles() {
    if (!fs.existsSync(this.config.RECORDINGS_PATH)) return [];
    return fs.readdirSync(this.config.RECORDINGS_PATH)
      .filter((f) => f.endsWith(".mp4"))
      .map((f) => {
        const stat = fs.statSync(path.join(this.config.RECORDINGS_PATH, f));
        return { name: f, size_mb: (stat.size / 1024 / 1024).toFixed(1), date: stat.mtime };
      })
      .sort((a, b) => new Date(b.date) - new Date(a.date));
  }
}

module.exports = RecordingManager;
