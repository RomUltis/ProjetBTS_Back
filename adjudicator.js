require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ModbusRTU = require("modbus-serial");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(cors());

// Servir les fichiers statiques (dashboard.html, .css, .js)
app.use(express.static("/var/www/html"));

// ─── CONFIG ─────────────────────────────────────────────────
const PORT = Number(process.env.PORT || 80);
const JWT_SECRET = process.env.JWT_SECRET;

// MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// PET-7067 — Sorties DO (Modbus/TCP)
const PET_DO_IP = process.env.PET_DO_IP || process.env.PET_IP;
const PET_DO_PORT = Number(process.env.PET_DO_PORT || 502);
const PET_DO_UNIT = Number(process.env.PET_DO_UNIT || 1);

// PET-7050 — Entrées DI (Modbus/TCP)
const PET_DI_IP = process.env.PET_DI_IP;
const PET_DI_PORT = Number(process.env.PET_DI_PORT || 502);
const PET_DI_UNIT = Number(process.env.PET_DI_UNIT || 1);
const DI_POLL_MS = Number(process.env.DI_POLL_MS || 1000);

// Limites sécurité
const PULSE_MS_DEFAULT = 1000;
const PULSE_MS_MIN = 100;
const PULSE_MS_MAX = 3000;
const TEST_DELAY_DEFAULT = 1200;

// Enregistrement caméra
const RTSP_URL = process.env.RTSP_URL || "";
const RECORDINGS_PATH = process.env.RECORDINGS_PATH || "/sftp/camciel1/upload";

// ─── CAMÉRAS (multi-cam) ────────────────────────────────────
// Construit la liste des caméras depuis les variables CAMn_*
function loadCameras() {
  const cams = [];
  for (let i = 1; i <= 8; i++) {
    const main = process.env[`CAM${i}_RTSP_MAIN`];
    const sub = process.env[`CAM${i}_RTSP_SUB`];
    if (!main && !sub) continue;
    cams.push({
      id: `cam${i}`,
      index: i,
      name: process.env[`CAM${i}_NAME`] || `Caméra ${i}`,
      type: process.env[`CAM${i}_TYPE`] || "generic",
      rtsp_main: main || "",
      rtsp_sub: sub || "",
      // URLs HLS publiques (servies par Apache ou static Express)
      hls_main: `/cam/cam${i}/main/live.m3u8`,
      hls_sub: `/cam/cam${i}/sub/live.m3u8`,
    });
  }
  // Fallback : si aucune CAMn_* mais RTSP_URL existe (ancien setup), expose cam1
  if (!cams.length && RTSP_URL) {
    cams.push({
      id: "cam1", index: 1, name: "Caméra principale", type: "dahua",
      rtsp_main: RTSP_URL, rtsp_sub: "",
      hls_main: "/cam/main/live.m3u8", hls_sub: "/cam/sub/live.m3u8",
    });
  }
  return cams;
}
const CAMERAS = loadCameras();
const ALARM_REC_CAM = `cam${Number(process.env.ALARM_REC_CAM || 1)}`;

function getCamById(id) {
  return CAMERAS.find(c => c.id === id) || null;
}

// ─── PIPELINE HLS (RTSP → HLS via FFmpeg) ──────────────────
// Spawn 1 process FFmpeg par cam × qualité, surveille et relance si crash.
// Active uniquement si HLS_ENABLE=true dans .env (pour pouvoir désactiver
// si un autre service gère déjà le HLS sur ce serveur).

const HLS_ENABLE = (process.env.HLS_ENABLE || "true").toLowerCase() !== "false";
const HLS_OUTPUT_PATH = process.env.HLS_OUTPUT_PATH || "/var/www/html/cam";
const HLS_SEGMENT_DURATION = Number(process.env.HLS_SEGMENT_DURATION || 2);
const HLS_LIST_SIZE = Number(process.env.HLS_LIST_SIZE || 4);

// État interne : { "cam1:main": { process, restartCount, lastStart, killed } }
const hlsStreams = {};

function startHlsStream(camId, quality, rtspUrl) {
  if (!rtspUrl) return;
  const key = `${camId}:${quality}`;
  const outDir = path.join(HLS_OUTPUT_PATH, camId, quality);

  try {
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  } catch (e) {
    console.error(`[HLS ${key}] Impossible de créer ${outDir}:`, e.message);
    return;
  }

  // Mode HLS configurable par cam via CAMn_HLS_MODE (default: copy)
  // - copy        : H.264 → segments .ts (le plus léger CPU, le plus compatible)
  // - copy_fmp4   : HEVC/H.265 → segments .m4s en fMP4 (léger CPU, navigateurs modernes)
  // - h264        : transcode tout vers H.264 (universel, mais coûte du CPU)
  const cam = getCamById(camId);
  const camIdx = cam ? cam.index : 1;
  const mode = (process.env[`CAM${camIdx}_HLS_MODE`] || "copy").toLowerCase();

  let codecArgs, formatArgs;
  if (mode === "copy_fmp4") {
    // HEVC en HLS fMP4 (pas de re-encoding)
    codecArgs = ["-c:v", "copy", "-c:a", "aac"];
    formatArgs = [
      "-f", "hls",
      "-hls_time", String(HLS_SEGMENT_DURATION),
      "-hls_list_size", String(HLS_LIST_SIZE),
      "-hls_flags", "delete_segments+omit_endlist+independent_segments",
      "-hls_segment_type", "fmp4",
      "-hls_fmp4_init_filename", "init.mp4",
      "-hls_segment_filename", path.join(outDir, "seg_%05d.m4s"),
    ];
  } else if (mode === "h264") {
    // Transcode H.265 (ou autre) → H.264 dans des .ts (universel)
    codecArgs = [
      "-c:v", "libx264",
      "-preset", "veryfast",
      "-tune", "zerolatency",
      "-c:a", "aac",
    ];
    formatArgs = [
      "-f", "hls",
      "-hls_time", String(HLS_SEGMENT_DURATION),
      "-hls_list_size", String(HLS_LIST_SIZE),
      "-hls_flags", "delete_segments+omit_endlist",
      "-hls_segment_filename", path.join(outDir, "seg_%05d.ts"),
    ];
  } else {
    // copy (défaut) : H.264 directement en .ts
    codecArgs = ["-c:v", "copy", "-c:a", "aac"];
    formatArgs = [
      "-f", "hls",
      "-hls_time", String(HLS_SEGMENT_DURATION),
      "-hls_list_size", String(HLS_LIST_SIZE),
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
  const state = hlsStreams[key] || { restartCount: 0 };
  state.process = proc;
  state.lastStart = Date.now();
  state.killed = false;
  state.outDir = outDir;
  hlsStreams[key] = state;

  // Garde les ~20 dernières lignes de stderr pour les afficher si FFmpeg crash
  state.stderrBuffer = state.stderrBuffer || [];
  proc.stderr.on("data", (chunk) => {
    const lines = chunk.toString().split(/\r?\n/).filter(l => l.trim());
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
    // Crash : afficher les dernières lignes stderr pour comprendre pourquoi
    if (code !== 0 && state.stderrBuffer && state.stderrBuffer.length) {
      console.warn(`[HLS ${key}] ─── stderr FFmpeg (dernières lignes) ───`);
      for (const line of state.stderrBuffer) {
        console.warn(`[HLS ${key}]   ${line}`);
      }
      console.warn(`[HLS ${key}] ──────────────────────────────────────────`);
      state.stderrBuffer = []; // reset pour le prochain crash
    }

    state.restartCount++;
    const delay = Math.min(30000, 2000 + state.restartCount * 1000);
    console.warn(`[HLS ${key}] FFmpeg s'est arrêté (code ${code}) — relance dans ${delay}ms (essai #${state.restartCount})`);
    setTimeout(() => {
      if (!state.killed) startHlsStream(camId, quality, rtspUrl);
    }, delay);
  });

  // Masque le mot de passe RTSP dans le log au démarrage
  const safeUrl = rtspUrl.replace(/(rtsp:\/\/[^:]+:)[^@]+(@)/, "$1***$2");
  console.log(`[HLS ${key}] FFmpeg démarré → ${outDir}/live.m3u8 (source: ${safeUrl})`);
}

function stopAllHlsStreams() {
  for (const [key, state] of Object.entries(hlsStreams)) {
    state.killed = true;
    if (state.process) {
      try { state.process.kill("SIGINT"); } catch {}
    }
    console.log(`[HLS ${key}] kill envoyé`);
  }
}

function startAllHlsStreams() {
  if (!HLS_ENABLE) {
    console.log("[HLS] désactivé via HLS_ENABLE=false");
    return;
  }
  if (!CAMERAS.length) {
    console.log("[HLS] aucune caméra configurée, rien à démarrer");
    return;
  }

  // Crée le dossier racine + symlinks de rétrocompat
  try {
    if (!fs.existsSync(HLS_OUTPUT_PATH)) fs.mkdirSync(HLS_OUTPUT_PATH, { recursive: true });

    // Symlinks /cam/main → /cam/cam1/main et /cam/sub → /cam/cam1/sub
    // (pour que les anciens clients qui appellent /cam/sub/live.m3u8 continuent à marcher)
    const cam1 = getCamById("cam1");
    if (cam1) {
      const links = [
        { from: path.join(HLS_OUTPUT_PATH, "main"), to: path.join(HLS_OUTPUT_PATH, "cam1", "main") },
        { from: path.join(HLS_OUTPUT_PATH, "sub"),  to: path.join(HLS_OUTPUT_PATH, "cam1", "sub") },
      ];
      for (const { from, to } of links) {
        try {
          // Crée la cible si elle n'existe pas encore (FFmpeg le fera aussi mais autant être propre)
          fs.mkdirSync(to, { recursive: true });
          // Si "from" existe déjà comme dossier réel (ancien setup), on n'écrase pas
          if (fs.existsSync(from)) {
            const stat = fs.lstatSync(from);
            if (!stat.isSymbolicLink()) {
              console.warn(`[HLS] ${from} existe déjà comme vrai dossier, symlink ignoré`);
              continue;
            }
            fs.unlinkSync(from);
          }
          fs.symlinkSync(to, from);
        } catch (e) {
          console.warn(`[HLS] symlink ${from} → ${to} : ${e.message}`);
        }
      }
    }
  } catch (e) {
    console.error("[HLS] préparation dossiers:", e.message);
  }

  console.log(`[HLS] Démarrage des flux pour ${CAMERAS.length} cam(s) → ${HLS_OUTPUT_PATH}`);
  for (const cam of CAMERAS) {
    if (cam.rtsp_main) startHlsStream(cam.id, "main", cam.rtsp_main);
    if (cam.rtsp_sub)  startHlsStream(cam.id, "sub",  cam.rtsp_sub);
  }
}

// Arrêter proprement les FFmpeg quand le serveur s'arrête
function gracefulShutdown(signal) {
  console.log(`\n[HLS] Signal ${signal} reçu, arrêt des flux FFmpeg…`);
  stopAllHlsStreams();
  setTimeout(() => process.exit(0), 1000); // laisse le temps aux kill de partir
}
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// Route admin pour redémarrer manuellement un flux HLS (utile pour debug)
// (à mettre à la fin avec les autres routes mais on la déclare ici pour la cohérence)

// ─── MAPPING DI / DO / ZONES ────────────────────────────────

const ZONES = {
  ciel1: { label: "Labo CIEL 1" },
  ciel2: { label: "Labo CIEL 2" },
  physique: { label: "Labo Serveur / Physique" },
};

// Entrées DI — PET-7050
// Tous inversés : la PET-7050 renvoie HIGH = repos/fermé, LOW = alerte/ouvert
const DI_MAP = [
  { ch: 4, zone: "ciel1", label: "Détecteur mouvement CIEL 1", type: "mouvement", inverted: true },
  { ch: 5, zone: "ciel1", label: "Porte transition CIEL 1-2 / fenêtre", type: "porte", inverted: true },
  { ch: 6, zone: "ciel2", label: "Détecteur mouvement CIEL 2", type: "mouvement", inverted: true },
  { ch: 7, zone: "ciel2", label: "Porte CIEL 2 + fenêtre", type: "porte", inverted: true },
  { ch: 8, zone: "physique", label: "Détecteur mouvement Physique", type: "mouvement", inverted: true },
  { ch: 9, zone: "physique", label: "Portes Physique + fenêtre + bureau", type: "porte", inverted: true },
];

// Sorties DO — PET-7067
const DO_MAP = [
  { ch: 0, zone: "ciel1", role: "gache", label: "Gâche" },
  { ch: 1, zone: "ciel1", role: "flash", label: "Flash" },
  { ch: 2, zone: "ciel1", role: "sirene", label: "Sirène" },
  { ch: 3, zone: "ciel2", role: "flash", label: "Flash" },
  { ch: 4, zone: "ciel2", role: "sirene", label: "Sirène" },
  { ch: 7, zone: "physique", role: "flash", label: "Flash" },
  { ch: 6, zone: "physique", role: "sirene", label: "Sirène" },
];

// ─── MySQL connect ──────────────────────────────────────────
db.connect((err) => {
  if (err) { console.error("Erreur connexion MySQL:", err); process.exit(1); }
  console.log("Connecté à MySQL");
});

// Helper promisifié pour les queries
function dbQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) reject(err); else resolve(results);
    });
  });
}

// ─── AUTH ────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ ok: false, error: "Token manquant" });
  }
  try {
    req.user = jwt.verify(parts[1], JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "Token invalide" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ ok: false, error: "Accès réservé aux administrateurs" });
  }
  return next();
}

// ─── Register / Login ───────────────────────────────────────
app.post("/register", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Vous devez être connecté avec un compte administrateur pour créer un compte."
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: "Session invalide ou expirée."
      });
    }

    // Vérification du rôle admin
    if (!decoded.role || decoded.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Accès refusé : seul un administrateur peut créer un compte."
      });
    }

    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Données manquantes"
      });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    db.query(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
      [username, hashedPassword, "user"],
      (err) => {
        if (err) {
          return res.status(500).json({
            success: false,
            message: "Nom d'utilisateur déjà utilisé (ou erreur DB)"
          });
        }

        return res.json({
          success: true,
          message: "Compte créé"
        });
      }
    );
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Données manquantes" });
  }
  db.query(
    "SELECT id, password_hash, role FROM users WHERE username = ?",
    [username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(401).json({ success: false, message: "Identifiants incorrects" });
      }
      const user = results[0];
      if (!bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ success: false, message: "Identifiants incorrects" });
      }
      const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "2h" });
      return res.json({ success: true, role: user.role, userId: user.id, token });
    }
  );
});

// ─── PET-7067 — Sorties DO (Modbus/TCP) ─────────────────────
const petDO = new ModbusRTU();
let petDOConnecting = null;

async function petDOConnect() {
  if (petDO.isOpen) return;
  if (!petDOConnecting) {
    petDOConnecting = (async () => {
      await petDO.connectTCP(PET_DO_IP, { port: PET_DO_PORT });
      petDO.setID(PET_DO_UNIT);
      petDO.setTimeout(1500);
      console.log(`PET-DO connecté: ${PET_DO_IP}:${PET_DO_PORT} (unit ${PET_DO_UNIT})`);
    })().finally(() => { petDOConnecting = null; });
  }
  await petDOConnecting;
}

async function petWriteCoil(channel, value) {
  await petDOConnect();
  await petDO.writeCoil(channel, !!value);
}

async function petPulseCoil(channel, ms) {
  await petWriteCoil(channel, true);
  setTimeout(async () => {
    try { await petWriteCoil(channel, false); }
    catch (e) { console.error(`PET-DO OFF failed (DO${channel}):`, e?.message || e); }
  }, ms);
}

function clampMs(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n)) return PULSE_MS_DEFAULT;
  return Math.min(PULSE_MS_MAX, Math.max(PULSE_MS_MIN, n));
}

// ─── PET-7050 — Entrées DI (Modbus/TCP) ─────────────────────
const petDI = new ModbusRTU();
let petDIConnecting = null;

async function petDIConnect() {
  if (petDI.isOpen) return;
  if (!petDIConnecting) {
    petDIConnecting = (async () => {
      await petDI.connectTCP(PET_DI_IP, { port: PET_DI_PORT });
      petDI.setID(PET_DI_UNIT);
      petDI.setTimeout(1500);
      console.log(`PET-DI connecté: ${PET_DI_IP}:${PET_DI_PORT} (unit ${PET_DI_UNIT})`);
    })().finally(() => { petDIConnecting = null; });
  }
  await petDIConnecting;
}

// Lecture de N discrete inputs à partir de l'adresse 0
async function readDI() {
  await petDIConnect();
  // Lire 18 DI (PET-7050 a DI0..DI17)
  const result = await petDI.readDiscreteInputs(0, 18);
  return result.data; // tableau de booleans
}

// ─── ÉTAT DI EN MÉMOIRE + POLLING ───────────────────────────
let lastDIState = {};    // { 4: false, 5: false, ... }
let currentDIState = {}; // idem, mis à jour par le polling
let alarmTriggered = false;
let alarmTriggerInfo = null;
let sirenActiveUntil = 0;  // timestamp (ms) jusqu'auquel les sirènes restent actives
let sirenChannelsActive = []; // channels sirène actuellement ON

// ─── MODE ENROLLMENT RFID ──────────────────────────────────
let enrollMode = {
  active: false,
  startedAt: 0,       // timestamp ms
  expiresAt: 0,       // timestamp ms
  detectedUid: null,   // UID détecté pendant l'enrollment
};

// ─── BIPS SONORES (activé/désactivé depuis le dashboard) ───
let beepEnabled = true;

// ─── ARMEMENT AUTOMATIQUE PAR HORAIRE ───────────────────────
let armedBySchedule = false;  // true si c'est le schedule qui a armé (pas un humain)

// Vérifie si l'heure actuelle est dans une plage horaire
function isInSchedule(slots) {
  if (!slots || slots.length === 0) return false;

  const now = new Date();
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const current = `${hh}:${mm}`;

  for (const slot of slots) {
    if (!slot.start || !slot.end) continue;

    if (slot.start <= slot.end) {
      // Plage simple : ex 08:00 → 18:00
      if (current >= slot.start && current < slot.end) return true;
    } else {
      // Plage qui traverse minuit : ex 21:00 → 07:00
      if (current >= slot.start || current < slot.end) return true;
    }
  }
  return false;
}

// Charger les plages horaires depuis MySQL
async function loadScheduleSlots() {
  try {
    const rows = await dbQuery("SELECT `id`, `start`, `end` FROM `schedule_slots` ORDER BY `id`");
    return rows;
  } catch (e) {
    console.error("loadScheduleSlots error:", e.message);
    return [];
  }
}

// Vérifie le schedule et arme/désarme automatiquement
async function checkSchedule() {
  try {
    const slots = await loadScheduleSlots();
    const inSchedule = isInSchedule(slots);
    const config = await loadAlarmConfig();

    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");

    console.log(`⏰ Schedule check: ${hh}:${mm} | ${slots.length} plage(s) | inSchedule=${inSchedule} | armed=${config.armed} | armedBySchedule=${armedBySchedule}`);

    if (inSchedule && !config.armed) {
      // On entre dans une plage → armer automatiquement
      // Vérifier que les portes sont fermées d'abord
      const openDoors = DI_MAP.filter(di => {
        if (di.type !== "porte") return false;
        const diZones = di.zone.split(",").map(z => z.trim());
        const inArmedZone = diZones.some(z => config.armed_zones.includes(z));
        if (!inArmedZone) return false;
        return !!currentDIState[di.ch];
      });

      if (openDoors.length > 0) {
        console.log(`⏰ Schedule: dans la plage mais porte(s) ouverte(s) → armement impossible (${openDoors.map(d => d.label).join(", ")})`);
        return;
      }

      config.armed = true;
      await saveAlarmConfig(config);
      armedBySchedule = true;
      console.log(`⏰ Schedule: ARMEMENT AUTOMATIQUE effectué`);

    } else if (!inSchedule && config.armed && armedBySchedule) {
      // On sort de la plage → désarmer SEULEMENT si pas d'alarme déclenchée
      if (alarmTriggered) {
        console.log(`⏰ Schedule: fin de plage mais alarme en cours → on ne désarme PAS`);
        return;
      }

      config.armed = false;
      await saveAlarmConfig(config);
      armedBySchedule = false;
      console.log(`⏰ Schedule: DÉSARMEMENT AUTOMATIQUE (fin de plage, aucune détection)`);
    }
  } catch (e) {
    console.error("checkSchedule error:", e.message);
  }
}

// Charger la config alarme depuis MySQL
async function loadAlarmConfig() {
  try {
    const rows = await dbQuery("SELECT * FROM alarm_config WHERE id = 1");
    if (rows.length === 0) return { armed: false, armed_zones: ["ciel1", "ciel2", "physique"], excluded_do: [0], siren_duration: 180 };
    const r = rows[0];
    return {
      armed: !!r.armed,
      armed_zones: typeof r.armed_zones === "string" ? JSON.parse(r.armed_zones) : r.armed_zones,
      excluded_do: typeof r.excluded_do === "string" ? JSON.parse(r.excluded_do) : r.excluded_do,
      siren_duration: r.siren_duration || 180,
    };
  } catch (e) {
    console.error("loadAlarmConfig error:", e.message);
    return { armed: false, armed_zones: ["ciel1", "ciel2", "physique"], excluded_do: [0], siren_duration: 180 };
  }
}

async function saveAlarmConfig(cfg) {
  await dbQuery(
    "UPDATE alarm_config SET armed=?, armed_zones=?, excluded_do=?, siren_duration=? WHERE id=1",
    [cfg.armed ? 1 : 0, JSON.stringify(cfg.armed_zones), JSON.stringify(cfg.excluded_do), cfg.siren_duration]
  );
}

// Logger un événement DI en base
async function logDIEvent(ch, value, triggered) {
  const diInfo = DI_MAP.find(d => d.ch === ch) || { zone: "?", label: `DI${ch}` };
  try {
    await dbQuery(
      "INSERT INTO di_events (channel, zone, label, value, triggered) VALUES (?, ?, ?, ?, ?)",
      [ch, diInfo.zone, diInfo.label, value ? 1 : 0, triggered ? 1 : 0]
    );
  } catch (e) {
    console.error("logDIEvent error:", e.message);
  }
}

// Déclencher l'alarme sur les DO appropriés
// → Active TOUTES les zones armées, pas seulement celle du capteur déclenché
async function triggerAlarm(diChannel, config) {
  const diInfo = DI_MAP.find(d => d.ch === diChannel);
  if (!diInfo) return;

  // Vérifier que le DI est dans une zone armée
  const diZones = diInfo.zone.split(",").map(z => z.trim());
  const triggerZones = diZones.filter(z => config.armed_zones.includes(z));
  if (triggerZones.length === 0) return;

  alarmTriggered = true;
  alarmTriggerInfo = {
    diChannel,
    diLabel: diInfo.label,
    zones: triggerZones,
    allArmedZones: config.armed_zones,
    time: new Date().toISOString(),
  };

  const sirenMs = (config.siren_duration || 180) * 1000;
  sirenActiveUntil = Date.now() + sirenMs;

  console.log(`🚨 ALARME DÉCLENCHÉE par DI${diChannel} (${diInfo.label}) — sirène: ${config.siren_duration}s — activation: TOUTES les zones (y compris non surveillées)`);

  // Activer les DO de TOUTES les zones (pas seulement les armées)
  // Les zones exclues ne sont pas surveillées mais elles sonnent quand même
  // Seules les exclusions DO individuelles sont respectées
  const dosToActivate = DO_MAP.filter(d => {
    if (config.excluded_do.includes(d.ch)) return false;
    return true; // toutes les zones sonnent
  });

  sirenChannelsActive = [];

  for (const doItem of dosToActivate) {
    try {
      await petWriteCoil(doItem.ch, true);
      console.log(`  ✓ DO${doItem.ch} ON (${doItem.zone} — ${doItem.role})`);
      if (doItem.role === "sirene") {
        sirenChannelsActive.push(doItem.ch);
      }
    } catch (e) {
      console.error(`  ✗ DO${doItem.ch} ON failed:`, e?.message || e);
    }
  }

  // Lancer l'enregistrement automatique de la caméra
  startRecording("alarm");
}

// Vérifier périodiquement si les sirènes doivent être coupées
async function checkSirenTimeout() {
  if (!alarmTriggered || sirenChannelsActive.length === 0) return;
  if (Date.now() < sirenActiveUntil) return;

  // Temps écoulé → couper les sirènes
  console.log(`⏱ Timeout sirène atteint — coupure des sirènes`);
  for (const ch of sirenChannelsActive) {
    try {
      await petWriteCoil(ch, false);
      console.log(`  ⏱ DO${ch} OFF (sirène — timeout)`);
    } catch (e) {
      console.error(`  ✗ DO${ch} OFF (sirène timeout) failed:`, e?.message || e);
    }
  }
  sirenChannelsActive = [];
}

// Désarmer : tout couper + ouvrir la gâche
async function disarmAlarm() {
  sirenActiveUntil = 0;
  sirenChannelsActive = [];

  // Ouvrir la gâche (DO0, pulse 3s) pour permettre d'entrer
  try {
    await petPulseCoil(0, 3000);
    console.log("🔓 Gâche ouverte (désarmement)");
  } catch (e) {
    console.error("Gâche (désarmement) failed:", e?.message || e);
  }

  // Couper tous les DO (sauf gâche DO0 qui vient d'être pulsée)
  for (const doItem of DO_MAP) {
    if (doItem.role === "gache") continue;
    try {
      await petWriteCoil(doItem.ch, false);
    } catch (e) {
      console.error(`Disarm DO${doItem.ch} OFF failed:`, e?.message || e);
    }
  }

  alarmTriggered = false;
  alarmTriggerInfo = null;

  // Arrêter l'enregistrement automatique s'il est en cours
  const autoRec = recordings[ALARM_REC_CAM];
  if (autoRec && autoRec.autoAlarm) {
    stopRecording(ALARM_REC_CAM);
    console.log("🔓 Enregistrement alarme arrêté automatiquement");
  }

  console.log("🔓 Alarme désarmée — tous les DO coupés");
}

// Polling DI
let pollInterval = null;

async function pollDI() {
  try {
    // Vérifier si les sirènes doivent être coupées
    await checkSirenTimeout();

    const bits = await readDI();
    const config = await loadAlarmConfig();

    for (const di of DI_MAP) {
      const rawVal = !!bits[di.ch];
      // Pour les contacts NF (portes/fenêtres) : HIGH = fermé = OK → on inverse
      // triggered = true signifie "en alerte" (porte ouverte ou mouvement détecté)
      const triggered = di.inverted ? !rawVal : rawVal;
      const prev = lastDIState[di.ch];
      currentDIState[di.ch] = triggered;

      // Changement détecté
      if (prev !== undefined && prev !== triggered) {
        console.log(`DI${di.ch} changé: ${prev} → ${triggered} (${di.label})`);
        const willTrigger = config.armed && triggered && !alarmTriggered;

        // Logger uniquement si l'alarme est armée
        if (config.armed) {
          await logDIEvent(di.ch, triggered, willTrigger);
        }

        // Si alarme armée et DI passe en alerte → déclencher
        if (willTrigger) {
          await triggerAlarm(di.ch, config);
        }
      }

      lastDIState[di.ch] = triggered;
    }
  } catch (e) {
    console.error("pollDI error:", e?.message || e);
    // Tenter reconnexion
    if (petDI.isOpen) {
      try { petDI.close(); } catch {}
    }
  }
}

function startPolling() {
  if (pollInterval) return;
  console.log(`Polling DI démarré (${DI_POLL_MS}ms)`);
  pollInterval = setInterval(pollDI, DI_POLL_MS);
  // Première lecture immédiate
  pollDI();

  // Vérification du schedule toutes les 30s
  setInterval(checkSchedule, 30000);
  checkSchedule(); // vérif immédiate au démarrage
}

// ─── ROUTES API ─────────────────────────────────────────────

app.get("/api/ping", (req, res) => res.json({ ok: true, msg: "adjudicator up" }));

// ── Config alarme ──

// GET /api/alarm/status
app.get("/api/alarm/status", requireAuth, async (req, res) => {
  try {
    const config = await loadAlarmConfig();
    res.json({
      ok: true,
      armed: config.armed,
      armed_zones: config.armed_zones,
      excluded_do: config.excluded_do,
      siren_duration: config.siren_duration,
      alarm_triggered: alarmTriggered,
      alarm_info: alarmTriggerInfo,
      armed_by_schedule: armedBySchedule,
      beep_enabled: beepEnabled,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Compat ancienne route
app.get("/alarm/status", requireAuth, async (req, res) => {
  try {
    const config = await loadAlarmConfig();
    res.json({ armed: config.armed });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /api/alarm/arm — armement avancé
// body: { armed: true, zones: ["ciel1","ciel2"], excluded_do: [0], siren_duration: 180 }
app.post("/api/alarm/arm", requireAuth, requireAdmin, async (req, res) => {
  try {
    const config = await loadAlarmConfig();
    const { armed, zones, excluded_do, siren_duration, beep } = req.body;

    // Mettre à jour l'état des bips
    if (typeof beep === "boolean") beepEnabled = beep;

    if (Array.isArray(zones)) config.armed_zones = zones.filter(z => ZONES[z]);
    if (Array.isArray(excluded_do)) config.excluded_do = [...new Set(excluded_do.map(Number).filter(n => Number.isInteger(n) && n >= 0 && n <= 7))];
    if (typeof siren_duration === "number" && siren_duration > 0) config.siren_duration = Math.min(600, siren_duration);

    // Si on tente d'armer → vérifier que toutes les portes/fenêtres sont fermées
    if (armed === true && !config.armed) {
      const openDoors = DI_MAP.filter(di => {
        if (di.type !== "porte") return false;
        // Vérifier si ce DI est dans une zone qu'on veut armer
        const diZones = di.zone.split(",").map(z => z.trim());
        const inArmedZone = diZones.some(z => config.armed_zones.includes(z));
        if (!inArmedZone) return false;
        // currentDIState stocke déjà la valeur logique (true = déclenché/ouvert)
        return !!currentDIState[di.ch];
      });

      if (openDoors.length > 0) {
        const names = openDoors.map(d => d.label).join(", ");
        return res.status(400).json({
          ok: false,
          error: `Impossible d'armer : porte(s)/fenêtre(s) ouverte(s) → ${names}`,
          open_doors: openDoors.map(d => ({ ch: d.ch, label: d.label, zone: d.zone })),
        });
      }
    }

    const wasArmed = config.armed;

    if (typeof armed === "boolean") config.armed = armed;

    // Armement/désarmement manuel → le schedule ne doit pas interférer
    if (typeof armed === "boolean") armedBySchedule = false;

    await saveAlarmConfig(config);

    // Double bip seulement si on PASSE de désarmé à armé
    if (config.armed && !wasArmed && beepEnabled) {
      const bipDOs = DO_MAP.filter(d => d.role !== "gache");
      for (let bip = 0; bip < 2; bip++) {
        for (const doItem of bipDOs) {
          try { await petWriteCoil(doItem.ch, true); } catch {}
        }
        await new Promise(r => setTimeout(r, 150));
        for (const doItem of bipDOs) {
          try { await petWriteCoil(doItem.ch, false); } catch {}
        }
        if (bip === 0) await new Promise(r => setTimeout(r, 150));
      }
      console.log(`🔔🔔 Double bip armement (dashboard)`);
    }

    // Bip simple seulement si on PASSE de armé à désarmé
    if (!config.armed && wasArmed && beepEnabled) {
      const bipDOs = DO_MAP.filter(d => d.role !== "gache");
      for (const doItem of bipDOs) {
        try { await petWriteCoil(doItem.ch, true); } catch {}
      }
      await new Promise(r => setTimeout(r, 150));
      for (const doItem of bipDOs) {
        try { await petWriteCoil(doItem.ch, false); } catch {}
      }
      console.log(`🔔 Bip désarmement (dashboard)`);
    }

    if (!config.armed && alarmTriggered) {
      await disarmAlarm();
    }
    if (!config.armed) {
      alarmTriggered = false;
      alarmTriggerInfo = null;
    }

    res.json({ ok: true, config });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Compat ancienne route toggle
app.post("/alarm/toggle", requireAuth, requireAdmin, async (req, res) => {
  try {
    const config = await loadAlarmConfig();
    const desired = !!req.body.armed;

    // Si on tente d'armer → vérifier portes/fenêtres
    if (desired && !config.armed) {
      const openDoors = DI_MAP.filter(di => {
        if (di.type !== "porte") return false;
        const diZones = di.zone.split(",").map(z => z.trim());
        const inArmedZone = diZones.some(z => config.armed_zones.includes(z));
        if (!inArmedZone) return false;
        return !!currentDIState[di.ch];
      });
      if (openDoors.length > 0) {
        const names = openDoors.map(d => d.label).join(", ");
        return res.status(400).json({
          ok: false,
          error: `Impossible d'armer : porte(s)/fenêtre(s) ouverte(s) → ${names}`,
        });
      }
    }

    config.armed = desired;
    armedBySchedule = false; // Armement manuel → schedule ne désarme pas
    await saveAlarmConfig(config);

    if (!config.armed && alarmTriggered) {
      await disarmAlarm();
    }
    if (!config.armed) {
      alarmTriggered = false;
      alarmTriggerInfo = null;
    }

    res.json({ ok: true, armed: config.armed });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /api/alarm/disarm — désarmement + coupure forcée
app.post("/api/alarm/disarm", requireAuth, requireAdmin, async (req, res) => {
  try {
    const config = await loadAlarmConfig();
    config.armed = false;
    armedBySchedule = false;
    await saveAlarmConfig(config);
    await disarmAlarm();
    res.json({ ok: true, msg: "Désarmé, tous les DO coupés" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Entrées DI ──

// GET /api/di/status — état actuel de toutes les DI
app.get("/api/di/status", requireAuth, async (req, res) => {
  try {
    const status = DI_MAP.map(di => ({
      ch: di.ch,
      zone: di.zone,
      label: di.label,
      type: di.type,
      value: !!currentDIState[di.ch],
    }));
    res.json({ ok: true, inputs: status, alarm_triggered: alarmTriggered, alarm_info: alarmTriggerInfo });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/di/read — lecture forcée (refresh à la demande)
app.get("/api/di/read", requireAuth, async (req, res) => {
  try {
    const bits = await readDI();
    const status = DI_MAP.map(di => {
      const rawVal = !!bits[di.ch];
      return {
        ch: di.ch,
        zone: di.zone,
        label: di.label,
        type: di.type,
        value: di.inverted ? !rawVal : rawVal,
      };
    });
    res.json({ ok: true, inputs: status });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/di/events — historique des événements
// query: ?limit=50&channel=4&triggered=1
app.get("/api/di/events", requireAuth, async (req, res) => {
  try {
    let sql = "SELECT * FROM di_events";
    const conditions = [];
    const params = [];

    if (req.query.channel !== undefined) {
      conditions.push("channel = ?");
      params.push(Number(req.query.channel));
    }
    if (req.query.triggered !== undefined) {
      conditions.push("triggered = ?");
      params.push(Number(req.query.triggered));
    }
    if (req.query.zone) {
      conditions.push("zone LIKE ?");
      params.push(`%${req.query.zone}%`);
    }

    if (conditions.length) sql += " WHERE " + conditions.join(" AND ");
    sql += " ORDER BY created_at DESC";

    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 100));
    sql += ` LIMIT ${limit}`;

    const rows = await dbQuery(sql, params);
    res.json({ ok: true, events: rows, count: rows.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/di/mapping — retourne le mapping DI pour le front
app.get("/api/di/mapping", requireAuth, (req, res) => {
  res.json({ ok: true, inputs: DI_MAP, outputs: DO_MAP, zones: ZONES });
});

// ── Sorties DO (existant, inchangé) ──

app.post("/api/pet/do/pulse", requireAuth, requireAdmin, async (req, res) => {
  try {
    const channel = Number(req.body?.channel);
    const ms = clampMs(req.body?.ms ?? PULSE_MS_DEFAULT);
    if (!Number.isInteger(channel) || channel < 0 || channel > 7) {
      return res.status(400).json({ ok: false, error: "channel must be 0..7" });
    }
    await petPulseCoil(channel, ms);
    return res.json({ ok: true, channel, ms });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post("/api/pet/do/test-all", requireAuth, requireAdmin, async (req, res) => {
  try {
    const ms = clampMs(req.body?.ms ?? PULSE_MS_DEFAULT);
    const delay = Math.min(5000, Math.max(200, Number(req.body?.delay ?? TEST_DELAY_DEFAULT)));
    (async () => {
      for (let ch = 0; ch <= 7; ch++) {
        try { await petPulseCoil(ch, ms); }
        catch (e) { console.error(`Test DO${ch} failed:`, e?.message || e); }
        await new Promise((r) => setTimeout(r, delay));
      }
    })();
    return res.json({ ok: true, action: "test_all", ms, delay });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post("/api/pet/do/test-selected", requireAuth, requireAdmin, async (req, res) => {
  try {
    const ms = clampMs(req.body?.ms ?? PULSE_MS_DEFAULT);
    const delay = Math.min(5000, Math.max(200, Number(req.body?.delay ?? TEST_DELAY_DEFAULT)));
    const channels = Array.isArray(req.body?.channels) ? req.body.channels : [];
    const clean = [...new Set(channels.map(Number))].filter(n => Number.isInteger(n) && n >= 0 && n <= 7);
    if (clean.length === 0) return res.status(400).json({ ok: false, error: "Aucun relais sélectionné" });

    (async () => {
      for (const ch of clean) {
        try { await petPulseCoil(ch, ms); }
        catch (e) { console.error(`Test DO${ch} failed:`, e?.message || e); }
        await new Promise(r => setTimeout(r, delay));
      }
    })();

    return res.json({ ok: true, action: "test_selected", channels: clean, ms, delay });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ── Routes existantes proxifiées (schedule, rfid) ──

// --- SCHEDULE ---

// GET /schedule — récupérer les plages horaires
app.get("/schedule", requireAuth, async (req, res) => {
  try {
    const rows = await dbQuery("SELECT `id`, `start`, `end` FROM `schedule_slots` ORDER BY `id`");
    res.json({ slots: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// PUT /schedule — remplacer toutes les plages
app.put("/schedule", requireAuth, requireAdmin, async (req, res) => {
  try {
    const slots = Array.isArray(req.body?.slots) ? req.body.slots : [];
    await dbQuery("DELETE FROM `schedule_slots`");
    for (const s of slots) {
      if (s.start && s.end) {
        await dbQuery("INSERT INTO `schedule_slots` (`start`, `end`) VALUES (?, ?)", [s.start, s.end]);
      }
    }
    res.json({ ok: true, slots });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- GESTION DES UTILISATEURS (admin only) ---

// GET /api/users — liste des utilisateurs
app.get("/api/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const rows = await dbQuery("SELECT id, username, role FROM users ORDER BY id");
    res.json({ ok: true, users: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// PATCH /api/users/:id/role — changer le rôle d'un utilisateur
app.patch("/api/users/:id/role", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { role } = req.body || {};
    const userId = Number(req.params.id);

    if (!["admin", "user"].includes(role)) {
      return res.status(400).json({ ok: false, error: "Rôle invalide (admin ou user)" });
    }

    // Empêcher de se rétrograder soi-même
    if (userId === req.user.id && role !== "admin") {
      return res.status(400).json({ ok: false, error: "Tu ne peux pas te rétrograder toi-même" });
    }

    await dbQuery("UPDATE users SET role = ? WHERE id = ?", [role, userId]);
    console.log(`[USERS] Rôle de user #${userId} changé → ${role}`);
    res.json({ ok: true, message: `Rôle mis à jour → ${role}` });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// DELETE /api/users/:id — supprimer un utilisateur
app.delete("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    // Empêcher de se supprimer soi-même
    if (userId === req.user.id) {
      return res.status(400).json({ ok: false, error: "Tu ne peux pas supprimer ton propre compte" });
    }

    await dbQuery("DELETE FROM users WHERE id = ?", [userId]);
    console.log(`[USERS] User #${userId} supprimé`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- RFID BADGES ---

// GET /rfid — liste des badges
app.get("/rfid", requireAuth, async (req, res) => {
  try {
    const rows = await dbQuery("SELECT * FROM rfid_badges ORDER BY created_at DESC");
    res.json({ badges: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /rfid — ajouter un badge
app.post("/rfid", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { uid, owner, enabled } = req.body || {};
    if (!uid) return res.status(400).json({ ok: false, error: "UID requis" });
    await dbQuery(
      "INSERT INTO rfid_badges (uid, owner, enabled) VALUES (?, ?, ?)",
      [uid, owner || "", enabled !== undefined ? (enabled ? 1 : 0) : 1]
    );
    res.json({ ok: true, message: "Badge ajouté" });
  } catch (e) {
    if (e.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ ok: false, error: "Ce badge existe déjà" });
    }
    res.status(500).json({ ok: false, error: e.message });
  }
});

// PATCH /rfid/:id — activer/désactiver un badge
app.patch("/rfid/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { enabled } = req.body || {};
    const id = req.params.id;
    // id peut être un int ou un uid
    const isNum = /^\d+$/.test(id);
    if (isNum) {
      await dbQuery("UPDATE rfid_badges SET enabled=? WHERE id=?", [enabled ? 1 : 0, Number(id)]);
    } else {
      await dbQuery("UPDATE rfid_badges SET enabled=? WHERE uid=?", [enabled ? 1 : 0, id]);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// DELETE /rfid/:id — supprimer un badge
app.delete("/rfid/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const isNum = /^\d+$/.test(id);
    if (isNum) {
      await dbQuery("DELETE FROM rfid_badges WHERE id=?", [Number(id)]);
    } else {
      await dbQuery("DELETE FROM rfid_badges WHERE uid=?", [id]);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/rfid/scan", async (req, res) => {
  try {
    const { card_id, raw_hex, wiegand_type } = req.body || {};
 
    if (!card_id) {
      return res.status(400).json({ ok: false, error: "card_id manquant" });
    }
 
    console.log(`[RFID] Scan reçu: card_id=${card_id}, raw=${raw_hex}, type=W${wiegand_type}`);

    // ── Mode enrollment actif ? ──
    if (enrollMode.active && Date.now() < enrollMode.expiresAt) {
      console.log(`[RFID] Mode enrollment → badge capturé: ${card_id}`);
      enrollMode.detectedUid = card_id;
      enrollMode.active = false; // arrêter l'enrollment
      return res.json({ ok: true, enrollment: true, message: "Badge capturé pour enrollment" });
    }

    // Si enrollment expiré, le désactiver proprement
    if (enrollMode.active && Date.now() >= enrollMode.expiresAt) {
      enrollMode.active = false;
      enrollMode.detectedUid = null;
    }
 
    // ── Comportement normal ──
    // Chercher le badge dans la BDD (par UID)
    const rows = await dbQuery(
      "SELECT * FROM rfid_badges WHERE uid = ? LIMIT 1",
      [card_id]
    );
 
    if (rows.length === 0) {
      console.log(`[RFID] Badge inconnu: ${card_id}`);
 
      try {
        await dbQuery(
          "INSERT INTO di_events (channel, zone, label, old_val, new_val, triggered) VALUES (?, ?, ?, ?, ?, ?)",
          [-1, "rfid", `Badge inconnu: ${card_id}`, 0, 1, 0]
        );
      } catch (e) { /* ignore log errors */ }
 
      return res.json({ ok: true, authorized: false, message: "Badge inconnu" });
    }
 
    const badge = rows[0];
 
    if (!badge.enabled) {
      console.log(`[RFID] Badge désactivé: ${card_id} (${badge.owner})`);
      return res.json({ ok: true, authorized: false, message: "Badge désactivé" });
    }
 
    // Badge autorisé → toggle alarme
    console.log(`[RFID] ✓ Accès autorisé: ${badge.owner} (${card_id})`);

    // Toggle alarme
    const config = await loadAlarmConfig();
    let newArmedState;
    let alarmAction;

    if (config.armed) {
      // Désarmer
      config.armed = false;
      armedBySchedule = false;
      await saveAlarmConfig(config);
      if (alarmTriggered) {
        await disarmAlarm();
      } else {
        alarmTriggered = false;
        alarmTriggerInfo = null;
        // Ouvrir la gâche (pas d'alarme en cours, disarmAlarm ne sera pas appelé)
        try { await petPulseCoil(0, 3000); } catch {}
        console.log("[RFID] 🔓 Gâche ouverte (désarmement par badge)");
      }
      newArmedState = false;
      alarmAction = "disarmed";
      console.log(`[RFID] 🔓 Alarme DÉSARMÉE par ${badge.owner}`);

      // Bip simple de confirmation désarmement
      if (beepEnabled) {
        const bipDOs = DO_MAP.filter(d => d.role !== "gache");
        for (const doItem of bipDOs) {
          try { await petWriteCoil(doItem.ch, true); } catch {}
        }
        await new Promise(r => setTimeout(r, 150));
        for (const doItem of bipDOs) {
          try { await petWriteCoil(doItem.ch, false); } catch {}
        }
        console.log(`[RFID] 🔔 Bip désarmement`);
      }
    } else {
      // Armer — vérifier les portes d'abord
      const openDoors = DI_MAP.filter(di => {
        if (di.type !== "porte") return false;
        const diZones = di.zone.split(",").map(z => z.trim());
        const inArmedZone = diZones.some(z => config.armed_zones.includes(z));
        if (!inArmedZone) return false;
        return !!currentDIState[di.ch];
      });

      if (openDoors.length > 0) {
        const names = openDoors.map(d => d.label).join(", ");
        console.log(`[RFID] ⚠ Armement impossible — portes ouvertes: ${names}`);

        try {
          await dbQuery(
            "INSERT INTO di_events (channel, zone, label, old_val, new_val, triggered) VALUES (?, ?, ?, ?, ?, ?)",
            [-1, "rfid", `Armement refusé (portes ouvertes): ${badge.owner}`, 0, 1, 0]
          );
        } catch (e) { /* ignore */ }

        return res.json({
          ok: true,
          authorized: true,
          owner: badge.owner,
          alarm_action: "arm_failed",
          message: `Armement impossible — portes ouvertes: ${names}`,
        });
      }

      config.armed = true;
      armedBySchedule = false;
      await saveAlarmConfig(config);
      newArmedState = true;
      alarmAction = "armed";
      console.log(`[RFID] 🔒 Alarme ARMÉE par ${badge.owner}`);

      // Double bip de confirmation armement
      if (beepEnabled) {
        const bipDOs2 = DO_MAP.filter(d => d.role !== "gache");
        for (let bip = 0; bip < 2; bip++) {
          for (const doItem of bipDOs2) {
            try { await petWriteCoil(doItem.ch, true); } catch {}
          }
          await new Promise(r => setTimeout(r, 150));
          for (const doItem of bipDOs2) {
            try { await petWriteCoil(doItem.ch, false); } catch {}
          }
          if (bip === 0) await new Promise(r => setTimeout(r, 150));
        }
        console.log(`[RFID] 🔔🔔 Double bip armement`);
      }
    }
 
    try {
      await dbQuery(
        "INSERT INTO di_events (channel, zone, label, old_val, new_val, triggered) VALUES (?, ?, ?, ?, ?, ?)",
        [-1, "rfid", `${alarmAction === "armed" ? "Armement" : "Désarmement"} par ${badge.owner} (${card_id})`, 0, 1, 0]
      );
    } catch (e) { /* ignore log errors */ }
 
    return res.json({
      ok: true,
      authorized: true,
      owner: badge.owner,
      alarm_action: alarmAction,
      armed: newArmedState,
      message: alarmAction === "armed" ? "Alarme armée" : "Alarme désarmée",
    });
 
  } catch (e) {
    console.error("[RFID] Erreur scan:", e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ── RFID ENROLLMENT (détection automatique) ──

// POST /rfid/enroll/start — active le mode enrollment pour 60s
app.post("/rfid/enroll/start", requireAuth, requireAdmin, (req, res) => {
  const duration = 60000; // 60 secondes
  enrollMode.active = true;
  enrollMode.startedAt = Date.now();
  enrollMode.expiresAt = Date.now() + duration;
  enrollMode.detectedUid = null;

  console.log("[RFID] Mode enrollment activé pour 60s");

  // Auto-expiration
  setTimeout(() => {
    if (enrollMode.active && Date.now() >= enrollMode.expiresAt) {
      enrollMode.active = false;
      console.log("[RFID] Mode enrollment expiré");
    }
  }, duration + 500);

  res.json({ ok: true, message: "Mode enrollment activé", expiresAt: enrollMode.expiresAt });
});

// GET /rfid/enroll/status — état du mode enrollment
app.get("/rfid/enroll/status", requireAuth, (req, res) => {
  // Si expiré, désactiver
  if (enrollMode.active && Date.now() >= enrollMode.expiresAt) {
    enrollMode.active = false;
  }

  const remainingMs = enrollMode.active
    ? Math.max(0, enrollMode.expiresAt - Date.now())
    : 0;

  res.json({
    ok: true,
    active: enrollMode.active,
    detected_uid: enrollMode.detectedUid,
    remaining_seconds: Math.ceil(remainingMs / 1000),
  });
});

// POST /rfid/enroll/stop — arrêter manuellement l'enrollment
app.post("/rfid/enroll/stop", requireAuth, requireAdmin, (req, res) => {
  enrollMode.active = false;
  console.log("[RFID] Mode enrollment arrêté manuellement");
  res.json({ ok: true, detected_uid: enrollMode.detectedUid });
});

// ─── ENREGISTREMENT CAMÉRA (FFmpeg, multi-cam) ─────────────
//
// Stocke un état d'enregistrement par cam (id). Plusieurs cams peuvent
// enregistrer en parallèle. L'ancienne API mono-cam (sans cam_id) cible
// ALARM_REC_CAM par défaut → rétrocompatible avec le frontend existant.

const recordings = {}; // { [camId]: { process, startTime, filename, autoAlarm } }

function startRecording(source = "manual", camId = ALARM_REC_CAM) {
  const cam = getCamById(camId);
  if (!cam) return { ok: false, reason: "unknown_cam" };
  if (recordings[camId]) return { ok: false, reason: "already_recording" };

  const rtspUrl = cam.rtsp_main || RTSP_URL; // fallback ancien setup
  if (!rtspUrl) return { ok: false, reason: "no_rtsp_url" };

  try {
    if (!fs.existsSync(RECORDINGS_PATH)) {
      fs.mkdirSync(RECORDINGS_PATH, { recursive: true });
    }
  } catch (e) {
    console.error("[REC] Impossible de créer le dossier:", e.message);
    return { ok: false, reason: e.message };
  }

  const now = new Date();
  const ts = now.toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const prefix = source === "alarm" ? "alarme" : "rec";
  const filename = `${prefix}_${camId}_${ts}.mp4`;
  const filepath = path.join(RECORDINGS_PATH, filename);

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
  recordings[camId] = state;

  proc.stderr.on("data", () => {});

  proc.on("error", (err) => {
    console.error(`[REC ${camId}] Erreur FFmpeg:`, err.message);
    delete recordings[camId];
  });

  proc.on("close", (code) => {
    console.log(`[REC ${camId}] FFmpeg terminé (code ${code}) — ${filename}`);
    delete recordings[camId];
  });

  console.log(`[REC ${camId}] ⏺ Enregistrement démarré (${source}) → ${filepath}`);
  return { ok: true, cam_id: camId, filename, path: filepath };
}

function stopRecording(camId = ALARM_REC_CAM) {
  const state = recordings[camId];
  if (!state) return { ok: false, reason: "not_recording" };

  const filename = state.filename;
  const duration = Math.round((Date.now() - state.startTime) / 1000);
  state.process.kill("SIGINT");

  console.log(`[REC ${camId}] ⏹ Enregistrement arrêté — ${filename} (${duration}s)`);
  return { ok: true, cam_id: camId, filename, duration_seconds: duration };
}

// GET /api/cam/list — config des caméras pour le frontend
app.get("/api/cam/list", requireAuth, (req, res) => {
  // On expose les infos publiques uniquement (pas les URLs RTSP avec credentials)
  const list = CAMERAS.map(c => ({
    id: c.id,
    index: c.index,
    name: c.name,
    type: c.type,
    hls_main: c.hls_main,
    hls_sub: c.hls_sub,
  }));
  res.json({ ok: true, cameras: list, alarm_rec_cam: ALARM_REC_CAM });
});

// POST /api/cam/record/start — body optionnel { cam_id: "cam2" }
app.post("/api/cam/record/start", requireAuth, requireAdmin, (req, res) => {
  const camId = (req.body && req.body.cam_id) || ALARM_REC_CAM;
  const result = startRecording("manual", camId);
  if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
  res.json(result);
});

// POST /api/cam/record/stop — body optionnel { cam_id: "cam2" }
app.post("/api/cam/record/stop", requireAuth, requireAdmin, (req, res) => {
  const camId = (req.body && req.body.cam_id) || ALARM_REC_CAM;
  const result = stopRecording(camId);
  if (!result.ok) return res.status(400).json({ ok: false, error: result.reason });
  res.json(result);
});

// GET /api/cam/record/status — état global de tous les enregistrements
// Rétrocompat : champs racine (recording, filename, elapsed_seconds, auto_alarm)
// reflètent l'enregistrement de la cam d'alarme (cam par défaut).
app.get("/api/cam/record/status", requireAuth, (req, res) => {
  const byCam = {};
  for (const [camId, st] of Object.entries(recordings)) {
    byCam[camId] = {
      recording: true,
      filename: st.filename,
      elapsed_seconds: Math.round((Date.now() - st.startTime) / 1000),
      auto_alarm: st.autoAlarm,
    };
  }

  // Rétrocompat champs racine
  const defaultSt = recordings[ALARM_REC_CAM];
  if (!defaultSt) {
    return res.json({ ok: true, recording: false, by_cam: byCam });
  }

  const elapsed = Math.round((Date.now() - defaultSt.startTime) / 1000);
  res.json({
    ok: true,
    recording: true,
    filename: defaultSt.filename,
    elapsed_seconds: elapsed,
    auto_alarm: defaultSt.autoAlarm,
    by_cam: byCam,
  });
});

// GET /api/cam/recordings — liste des fichiers enregistrés
app.get("/api/cam/recordings", requireAuth, (req, res) => {
  try {
    if (!fs.existsSync(RECORDINGS_PATH)) {
      return res.json({ ok: true, files: [] });
    }
    const files = fs.readdirSync(RECORDINGS_PATH)
      .filter(f => f.endsWith(".mp4"))
      .map(f => {
        const stat = fs.statSync(path.join(RECORDINGS_PATH, f));
        return { name: f, size_mb: (stat.size / 1024 / 1024).toFixed(1), date: stat.mtime };
      })
      .sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json({ ok: true, files });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/cam/hls/status — état des flux HLS (admin)
app.get("/api/cam/hls/status", requireAuth, requireAdmin, (req, res) => {
  const streams = Object.entries(hlsStreams).map(([key, st]) => ({
    key,
    running: !!st.process,
    restart_count: st.restartCount || 0,
    uptime_seconds: st.lastStart ? Math.round((Date.now() - st.lastStart) / 1000) : 0,
    out_dir: st.outDir,
  }));
  res.json({ ok: true, enabled: HLS_ENABLE, streams });
});

// POST /api/cam/hls/restart — relancer un flux (body: { cam_id, quality })
app.post("/api/cam/hls/restart", requireAuth, requireAdmin, (req, res) => {
  const camId = req.body && req.body.cam_id;
  const quality = (req.body && req.body.quality) || "sub";
  const cam = getCamById(camId);
  if (!cam) return res.status(400).json({ ok: false, error: "unknown_cam" });
  const rtspUrl = quality === "main" ? cam.rtsp_main : cam.rtsp_sub;
  if (!rtspUrl) return res.status(400).json({ ok: false, error: "no_rtsp_url" });

  const key = `${camId}:${quality}`;
  const existing = hlsStreams[key];
  if (existing && existing.process) {
    existing.killed = true;
    try { existing.process.kill("SIGINT"); } catch {}
  }
  // Petit délai pour que FFmpeg libère le fichier .m3u8, puis relance
  setTimeout(() => startHlsStream(camId, quality, rtspUrl), 500);
  res.json({ ok: true, restarted: key });
});

// ─── DÉMARRAGE ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`adjudicator.js lancé sur le port ${PORT}`);
  console.log(`PET-DO: ${PET_DO_IP}:${PET_DO_PORT} (unit ${PET_DO_UNIT})`);
  console.log(`PET-DI: ${PET_DI_IP}:${PET_DI_PORT} (unit ${PET_DI_UNIT})`);
  console.log(`Caméras configurées : ${CAMERAS.length} (alarme → ${ALARM_REC_CAM})`);
  CAMERAS.forEach(c => console.log(`  - ${c.id} : ${c.name} (${c.type})`));
  startPolling();
  startAllHlsStreams();
});