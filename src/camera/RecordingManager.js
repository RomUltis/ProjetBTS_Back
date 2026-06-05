const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

// Un process FFmpeg par caméra (toutes les caméras enregistrent en parallèle
// lors d'une intrusion). Chaque caméra écrit son MP4 dans SON sous-dossier
// (RECORDINGS_PATH/<recFolder>/), correspondant à son dossier SFTP.
class RecordingManager {
  constructor({ config, cameras }) {
    this.config = config;
    this.cameras = cameras;
    this.recordings = {};
  }

  get(camId) {
    return this.recordings[camId];
  }

  // Dossier de destination d'une caméra (sous RECORDINGS_PATH).
  camDir(cam) {
    return path.join(this.config.RECORDINGS_PATH, cam.recFolder || cam.id);
  }

  start(source = "manual", camId = this.cameras.alarmRecCam) {
    const cam = this.cameras.getCamById(camId);
    if (!cam) return { ok: false, reason: "unknown_cam" };
    if (this.recordings[camId]) return { ok: false, reason: "already_recording" };

    const rtspUrl = cam.rtsp_main || this.config.RTSP_URL;
    if (!rtspUrl) {
      console.warn(`[REC ${camId}] pas d'URL RTSP → enregistrement ignoré`);
      return { ok: false, reason: "no_rtsp_url" };
    }

    const dir = this.camDir(cam);
    try {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    } catch (e) {
      console.error(`[REC ${camId}] impossible de créer ${dir}:`, e.message);
      return { ok: false, reason: e.message };
    }

    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const prefix = source === "alarm" ? "alarme" : "rec";
    const filename = `${prefix}_${camId}_${ts}.mp4`;
    const filepath = path.join(dir, filename);

    // Vidéo copiée (pas de réencodage), audio AAC OPTIONNEL (?) pour ne pas
    // échouer si la caméra n'a pas d'audio. MP4 FRAGMENTÉ (frag_keyframe +
    // empty_moov) : le fichier est écrit en fragments auto-suffisants, donc
    // reste LISIBLE même si FFmpeg s'arrête mal (code ≠ 255) ou si le flux a un
    // paquet invalide en fin de course → plus de .mp4 corrompu/illisible.
    const proc = spawn("ffmpeg", [
      "-hide_banner", "-loglevel", "warning",
      "-rtsp_transport", "tcp",
      "-i", rtspUrl,
      "-map", "0:v:0",
      "-map", "0:a:0?",
      "-c:v", "copy",
      "-c:a", "aac",
      "-movflags", "+frag_keyframe+empty_moov+default_base_moof",
      "-y",
      filepath,
    ]);

    const state = {
      process: proc,
      startTime: Date.now(),
      filename,
      filepath,
      autoAlarm: source === "alarm",
      camId,
      stderr: [],
    };
    this.recordings[camId] = state;

    // Garde les dernières lignes de stderr pour diagnostiquer un échec
    proc.stderr.on("data", (chunk) => {
      const lines = chunk.toString().split(/\r?\n/).filter((l) => l.trim());
      for (const line of lines) {
        state.stderr.push(line);
        if (state.stderr.length > 15) state.stderr.shift();
      }
    });

    proc.on("error", (err) => {
      console.error(`[REC ${camId}] erreur FFmpeg (spawn):`, err.message);
      delete this.recordings[camId];
    });

    proc.on("close", (code) => {
      // code 255 = arrêt par SIGINT (normal). Autre code non nul = problème.
      if (code && code !== 255 && state.stderr.length) {
        console.warn(`[REC ${camId}] FFmpeg s'est arrêté (code ${code}) — dernières lignes :`);
        for (const l of state.stderr) console.warn(`[REC ${camId}]   ${l}`);
      }
      console.log(`[REC ${camId}] FFmpeg terminé (code ${code}) — ${filename}`);
      delete this.recordings[camId];
    });

    const safeUrl = rtspUrl.replace(/(rtsp:\/\/[^:]+:)[^@]+(@)/, "$1***$2");
    console.log(`[REC ${camId}] ⏺ Enregistrement démarré (${source}) → ${filepath} (src: ${safeUrl})`);
    return { ok: true, cam_id: camId, filename, path: filepath };
  }

  // Démarre l'enregistrement de TOUTES les caméras configurées (intrusion).
  startAll(source = "alarm") {
    return this.cameras.cameras.map((cam) => ({ cam_id: cam.id, ...this.start(source, cam.id) }));
  }

  stop(camId = this.cameras.alarmRecCam) {
    const state = this.recordings[camId];
    if (!state) return { ok: false, reason: "not_recording" };

    const filename = state.filename;
    const duration = Math.round((Date.now() - state.startTime) / 1000);
    try { state.process.kill("SIGINT"); } catch {}

    console.log(`[REC ${camId}] ⏹ Enregistrement arrêté — ${filename} (${duration}s)`);
    return { ok: true, cam_id: camId, filename, duration_seconds: duration };
  }

  // Arrête tous les enregistrements en cours (par défaut, seulement ceux
  // déclenchés automatiquement par une alarme : autoAlarm).
  stopAll({ onlyAuto = true } = {}) {
    const results = [];
    for (const camId of Object.keys(this.recordings)) {
      if (onlyAuto && !this.recordings[camId].autoAlarm) continue;
      results.push(this.stop(camId));
    }
    return results;
  }

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

    const ids = Object.keys(this.recordings);
    if (ids.length === 0) return { ok: true, recording: false, by_cam: byCam };

    // Champs racine = un enregistrement en cours (rétrocompat dashboard).
    const st = this.recordings[this.cameras.alarmRecCam] || this.recordings[ids[0]];
    return {
      ok: true,
      recording: true,
      filename: st.filename,
      elapsed_seconds: Math.round((Date.now() - st.startTime) / 1000),
      auto_alarm: st.autoAlarm,
      by_cam: byCam,
    };
  }

  // Liste les MP4 de chaque sous-dossier de caméra.
  listFiles() {
    const root = this.config.RECORDINGS_PATH;
    if (!fs.existsSync(root)) return [];
    const files = [];
    for (const cam of this.cameras.cameras) {
      const dir = this.camDir(cam);
      if (!fs.existsSync(dir)) continue;
      for (const f of fs.readdirSync(dir)) {
        if (!f.endsWith(".mp4")) continue;
        try {
          const stat = fs.statSync(path.join(dir, f));
          files.push({
            name: f,
            cam_id: cam.id,
            folder: cam.recFolder || cam.id,
            size_mb: (stat.size / 1024 / 1024).toFixed(1),
            date: stat.mtime,
          });
        } catch {}
      }
    }
    return files.sort((a, b) => new Date(b.date) - new Date(a.date));
  }
}

module.exports = RecordingManager;
