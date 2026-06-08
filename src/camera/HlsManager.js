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
    this.lastAccess = {};   // dernier accès par flux (pour couper ceux qu'on ne regarde plus)
    this._startReaper();
  }

  startStream(camId, quality, rtspUrl, restartCount = 0) {
    if (!rtspUrl) return;
    const key = `${camId}:${quality}`;

    // Anti-doublon : coupe un éventuel FFmpeg encore vivant pour ce flux, sinon
    // deux process écriraient le même live.m3u8 → flux cassé au ré-armement.
    const prev = this.streams[key];
    if (prev && prev.process) { prev.killed = true; try { prev.process.kill("SIGKILL"); } catch {} }

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
      "-fflags", "+genpts+discardcorrupt",   // régénère les timestamps + jette les paquets corrompus
      "-err_detect", "ignore_err",           // n'abandonne pas sur une erreur de décodage
      "-rtsp_transport", "tcp",
      "-stimeout", "5000000",                // timeout 5s : si le flux SE FIGE, FFmpeg sort → relance auto (reconnexion)
      "-i", rtspUrl,
      ...codecArgs,
      ...formatArgs,
      path.join(outDir, "live.m3u8"),
    ];

    console.log(`[HLS ${key}] mode=${mode}`);
    const proc = spawn("ffmpeg", args);
    // Objet d'état NEUF à chaque démarrage (pas de réutilisation → pas de
    // confusion entre l'ancien et le nouveau process).
    const state = { process: proc, lastStart: Date.now(), killed: false, outDir, restartCount, stderrBuffer: [] };
    this.streams[key] = state;

    // Garde les ~20 dernières lignes de stderr pour diagnostiquer un crash
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
      // Process périmé (un nouveau l'a remplacé) ou flux stoppé → on ne relance pas.
      if (this.streams[key] !== state) return;
      state.process = null;
      if (state.killed) {
        console.log(`[HLS ${key}] arrêté (code ${code})`);
        return;
      }
      if (code !== 0 && state.stderrBuffer.length) {
        console.warn(`[HLS ${key}] ─── stderr FFmpeg (dernières lignes) ───`);
        for (const line of state.stderrBuffer) console.warn(`[HLS ${key}]   ${line}`);
        console.warn(`[HLS ${key}] ──────────────────────────────────────────`);
      }

      // S'il a tenu un bon moment, ce n'est pas un crash en boucle → compteur à 1
      const count = (Date.now() - state.lastStart > 30000) ? 1 : restartCount + 1;
      const delayMs = Math.min(4000, 500 * count); // relance RAPIDE (et non plus jusqu'à 30s)
      console.warn(`[HLS ${key}] FFmpeg s'est arrêté (code ${code}) — relance dans ${delayMs}ms (essai #${count})`);
      setTimeout(() => {
        if (this.streams[key] === state && !state.killed) this.startStream(camId, quality, rtspUrl, count);
      }, delayMs);
    });

    // Masque le mot de passe RTSP dans le log
    const safeUrl = rtspUrl.replace(/(rtsp:\/\/[^:]+:)[^@]+(@)/, "$1***$2");
    console.log(`[HLS ${key}] FFmpeg démarré → ${outDir}/live.m3u8 (source: ${safeUrl})`);
  }

  // Démarre un flux À LA DEMANDE quand le front réclame cette qualité (main/sub)
  // et mémorise l'accès. Ne fait rien s'il tourne déjà, si HLS désactivé, ou si
  // RGPD (désarmé). C'est ce qui permet au bouton main/sub du front de marcher
  // sans pré-lancer tous les flux.
  ensureStream(camId, quality) {
    if (quality !== "main" && quality !== "sub") return;
    const key = `${camId}:${quality}`;
    this.lastAccess[key] = Date.now();

    if (!this.config.hls.enable) return;
    if (this.config.rgpdCamsOnlyWhenArmed && !this.getArmed()) return;

    const st = this.streams[key];
    if (st && st.process && !st.killed) return; // déjà actif

    const cam = this.cameras.getCamById(camId);
    if (!cam) return;
    const rtspUrl = quality === "main" ? cam.rtsp_main : cam.rtsp_sub;
    if (!rtspUrl) return;

    console.log(`[HLS] ▶ démarrage à la demande de ${key}`);
    this.startStream(camId, quality, rtspUrl);
  }

  // Coupe les flux qui ne sont plus regardés (aucun accès depuis >30s) → on ne
  // garde actifs que les flux réellement affichés sur le front.
  _startReaper() {
    if (this._reaper) return;
    this._reaper = setInterval(() => {
      const now = Date.now();
      for (const [key, st] of Object.entries(this.streams)) {
        if (!st.process || st.killed) continue;
        const last = this.lastAccess[key] || st.lastStart || 0;
        if (now - last > 30000) {
          console.log(`[HLS] ⏹ ${key} arrêté (non regardé depuis >30s)`);
          st.killed = true;
          try { st.process.kill("SIGINT"); } catch {}
        }
      }
    }, 10000);
  }

  stopAll() {
    for (const [key, state] of Object.entries(this.streams)) {
      state.killed = true;
      if (state.process) {
        try { state.process.kill("SIGKILL"); } catch {} // SIGKILL : tue aussi un FFmpeg figé
      }
      console.log(`[HLS ${key}] arrêté`);
    }
    // On vide la table TOUT DE SUITE → ré-armement repart propre, sans doublon.
    this.streams = {};
    this.lastAccess = {};
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

    // On ne démarre que le flux SECONDAIRE (sub) par défaut. Le flux principal
    // (main) est lancé à la demande via ensureStream() quand le front le réclame.
    console.log(`[HLS] Démarrage du flux 'sub' pour ${this.cameras.length} cam(s) → ${this.config.hls.outputPath}`);
    for (const cam of this.cameras.cameras) {
      if (cam.rtsp_sub) this.startStream(cam.id, "sub", cam.rtsp_sub);
      else if (cam.rtsp_main) this.startStream(cam.id, "main", cam.rtsp_main);
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
      // Purge différée, mais SEULEMENT si on est toujours désarmé : sinon on
      // effacerait les segments d'un ré-armement intervenu entre-temps.
      setTimeout(() => { if (!this.getArmed()) this.purgeSegments(); }, 1500);
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
