const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

// Un process FFmpeg par cam × qualité (RTSP → HLS). Flux actifs seulement
// quand l'alarme est armée (RGPD), via applyRgpdState().
class HlsManager {
  constructor({ config, cameras, getArmed }) {
    this.config = config;
    this.cameras = cameras;
    this.getArmed = getArmed;
    this.streams = {};
  }

  startStream(camId, quality, rtspUrl) {
    if (!rtspUrl) return;
    const key = `${camId}:${quality}`;
    const outDir = path.join(this.config.hls.outputPath, camId, quality);

    try {
      if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    } catch (e) {
      console.error(`[HLS ${key}] Impossible de créer ${outDir}:`, e.message);
      return;
    }

    const cam = this.cameras.getCamById(camId);
    const mode = cam ? cam.hlsMode : "copy";

    let codecArgs, formatArgs;
    if (mode === "copy_fmp4") {
      // HEVC en HLS fMP4, sans réencodage
      codecArgs = ["-c:v", "copy", "-c:a", "aac"];
      formatArgs = [
        "-f", "hls",
        "-hls_time", String(this.config.hls.segmentDuration),
        "-hls_list_size", String(this.config.hls.listSize),
        "-hls_flags", "delete_segments+omit_endlist+independent_segments",
        "-hls_segment_type", "fmp4",
        "-hls_fmp4_init_filename", "init.mp4",
        "-hls_segment_filename", path.join(outDir, "seg_%05d.m4s"),
      ];
    } else if (mode === "h264") {
      // Transcode vers H.264 en .ts (lecture universelle)
      codecArgs = ["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-c:a", "aac"];
      formatArgs = [
        "-f", "hls",
        "-hls_time", String(this.config.hls.segmentDuration),
        "-hls_list_size", String(this.config.hls.listSize),
        "-hls_flags", "delete_segments+omit_endlist",
        "-hls_segment_filename", path.join(outDir, "seg_%05d.ts"),
      ];
    } else {
      // copy : H.264 directement en .ts
      codecArgs = ["-c:v", "copy", "-c:a", "aac"];
      formatArgs = [
        "-f", "hls",
        "-hls_time", String(this.config.hls.segmentDuration),
        "-hls_list_size", String(this.config.hls.listSize),
        "-hls_flags", "delete_segments+omit_endlist",
        "-hls_segment_filename", path.join(outDir, "seg_%05d.ts"),
      ];
    }

    const args = [
      "-hide_banner", "-loglevel", "warning",
      "-rtsp_transport", "tcp",
      "-i", rtspUrl,
      ...codecArgs,
      ...formatArgs,
      path.join(outDir, "live.m3u8"),
    ];

    console.log(`[HLS ${key}] mode=${mode}`);
    const proc = spawn("ffmpeg", args);
    const state = this.streams[key] || { restartCount: 0 };
    state.process = proc;
    state.lastStart = Date.now();
    state.killed = false;
    state.outDir = outDir;
    this.streams[key] = state;

    // Garde les ~20 dernières lignes de stderr pour diagnostiquer un crash
    state.stderrBuffer = state.stderrBuffer || [];
    proc.stderr.on("data", (chunk) => {
      const lines = chunk.toString().split(/\r?\n/).filter((l) => l.trim());
      for (const line of lines) {
        state.stderrBuffer.push(line);
        if (state.stderrBuffer.length > 20) state.stderrBuffer.shift();
      }
    });

    proc.on("error", (err) => {
      console.error(`[HLS ${key}] erreur spawn:`, err.message);
    });

    proc.on("close", (code) => {
      state.process = null;
      if (state.killed) {
        console.log(`[HLS ${key}] arrêté (code ${code})`);
        return;
      }
      if (code !== 0 && state.stderrBuffer && state.stderrBuffer.length) {
        console.warn(`[HLS ${key}] ─── stderr FFmpeg (dernières lignes) ───`);
        for (const line of state.stderrBuffer) {
          console.warn(`[HLS ${key}]   ${line}`);
        }
        console.warn(`[HLS ${key}] ──────────────────────────────────────────`);
        state.stderrBuffer = [];
      }

      state.restartCount++;
      const delayMs = Math.min(30000, 2000 + state.restartCount * 1000);
      console.warn(`[HLS ${key}] FFmpeg s'est arrêté (code ${code}) — relance dans ${delayMs}ms (essai #${state.restartCount})`);
      setTimeout(() => {
        if (!state.killed) this.startStream(camId, quality, rtspUrl);
      }, delayMs);
    });

    // Masque le mot de passe RTSP dans le log
    const safeUrl = rtspUrl.replace(/(rtsp:\/\/[^:]+:)[^@]+(@)/, "$1***$2");
    console.log(`[HLS ${key}] FFmpeg démarré → ${outDir}/live.m3u8 (source: ${safeUrl})`);
  }

  stopAll() {
    for (const [key, state] of Object.entries(this.streams)) {
      state.killed = true;
      if (state.process) {
        try { state.process.kill("SIGINT"); } catch {}
      }
      console.log(`[HLS ${key}] kill envoyé`);
    }
  }

  // RGPD : supprime tous les segments HLS du disque (aucune image résiduelle)
  purgeSegments() {
    let deletedFiles = 0;
    for (const cam of this.cameras.cameras) {
      for (const quality of ["main", "sub"]) {
        const dir = path.join(this.config.hls.outputPath, cam.id, quality);
        if (!fs.existsSync(dir)) continue;
        try {
          const files = fs.readdirSync(dir);
          for (const f of files) {
            if (/\.(m3u8|ts|m4s|mp4)$/.test(f)) {
              try { fs.unlinkSync(path.join(dir, f)); deletedFiles++; } catch {}
            }
          }
        } catch (e) {
          console.error(`[HLS] purge ${dir} error:`, e.message);
        }
      }
    }
    if (deletedFiles > 0) {
      console.log(`[RGPD] 🗑 ${deletedFiles} segment(s) HLS supprimé(s) du disque (conformité art. 5.1.c)`);
    }
  }

  startAll() {
    if (!this.config.hls.enable) {
      console.log("[HLS] désactivé via HLS_ENABLE=false");
      return;
    }
    if (!this.cameras.length) {
      console.log("[HLS] aucune caméra configurée, rien à démarrer");
      return;
    }

    try {
      if (!fs.existsSync(this.config.hls.outputPath)) fs.mkdirSync(this.config.hls.outputPath, { recursive: true });
    } catch (e) {
      console.error("[HLS] préparation dossiers:", e.message);
    }

    // RGPD : si désarmé, ne rien démarrer au boot
    if (this.config.rgpdCamsOnlyWhenArmed && !this.getArmed()) {
      console.log(`[HLS] 🛡 RGPD : flux non démarrés (alarme désarmée). Démarrage à l'arm().`);
      return;
    }

    console.log(`[HLS] Démarrage des flux pour ${this.cameras.length} cam(s) → ${this.config.hls.outputPath}`);
    for (const cam of this.cameras.cameras) {
      if (cam.rtsp_main) this.startStream(cam.id, "main", cam.rtsp_main);
      if (cam.rtsp_sub)  this.startStream(cam.id, "sub",  cam.rtsp_sub);
    }
  }

  // Synchronise les flux avec l'état alarme : armé → démarre, désarmé → coupe + purge
  applyRgpdState(armed) {
    if (!this.config.rgpdCamsOnlyWhenArmed) return;

    if (armed) {
      const anyRunning = Object.values(this.streams).some((s) => s.process && !s.killed);
      if (!anyRunning) {
        console.log("[RGPD] 🎥 Alarme armée → démarrage des flux HLS");
        this.startAll();
      }
    } else {
      console.log("[RGPD] 🛡 Alarme désarmée → arrêt FFmpeg + purge segments (art. 5.1.c)");
      this.stopAll();
      setTimeout(() => {
        this.purgeSegments();
        for (const key of Object.keys(this.streams)) delete this.streams[key];
      }, 1500);
    }
  }

  statusList() {
    return Object.entries(this.streams).map(([key, st]) => ({
      key,
      running: !!st.process,
      restart_count: st.restartCount || 0,
      uptime_seconds: st.lastStart ? Math.round((Date.now() - st.lastStart) / 1000) : 0,
      out_dir: st.outDir,
    }));
  }

  restart(camId, quality) {
    const cam = this.cameras.getCamById(camId);
    if (!cam) return { ok: false, error: "unknown_cam" };
    const rtspUrl = quality === "main" ? cam.rtsp_main : cam.rtsp_sub;
    if (!rtspUrl) return { ok: false, error: "no_rtsp_url" };

    const key = `${camId}:${quality}`;
    const existing = this.streams[key];
    if (existing && existing.process) {
      existing.killed = true;
      try { existing.process.kill("SIGINT"); } catch {}
    }
    setTimeout(() => this.startStream(camId, quality, rtspUrl), 500);
    return { ok: true, restarted: key };
  }
}

module.exports = HlsManager;
