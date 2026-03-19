require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ModbusRTU = require("modbus-serial");

const app = express();
app.use(express.json());
app.use(cors());

// ─── CONFIG ─────────────────────────────────────────────────
const PORT = Number(process.env.PORT);
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
  { ch: 5, zone: "ciel1,ciel2", label: "Porte transition CIEL 1-2 / fenêtre", type: "porte", inverted: true },
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

// ─── Register / Login ───────────────────────────────────────
app.post("/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Données manquantes" });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.query(
    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
    [username, hashedPassword, "user"],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: "Nom d'utilisateur déjà utilisé (ou erreur DB)" });
      return res.json({ success: true, message: "Compte créé" });
    }
  );
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

  console.log(`🚨 ALARME DÉCLENCHÉE par DI${diChannel} (${diInfo.label}) — sirène: ${config.siren_duration}s — activation: TOUTES zones armées (${config.armed_zones.join(", ")})`);

  // Activer les DO de TOUTES les zones armées (hors exclusions)
  const dosToActivate = DO_MAP.filter(d => {
    if (config.excluded_do.includes(d.ch)) return false;
    return config.armed_zones.includes(d.zone);
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

// Désarmer : tout couper
async function disarmAlarm() {
  sirenActiveUntil = 0;
  sirenChannelsActive = [];

  // Couper tous les DO (sauf gâche DO0 qui est contrôle d'accès)
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
        await logDIEvent(di.ch, triggered, willTrigger);

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
app.post("/api/alarm/arm", requireAuth, async (req, res) => {
  try {
    const config = await loadAlarmConfig();
    const { armed, zones, excluded_do, siren_duration } = req.body;

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

    if (typeof armed === "boolean") config.armed = armed;

    await saveAlarmConfig(config);

    // Si désarmement → couper les DO
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
app.post("/alarm/toggle", requireAuth, async (req, res) => {
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
app.post("/api/alarm/disarm", requireAuth, async (req, res) => {
  try {
    const config = await loadAlarmConfig();
    config.armed = false;
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

app.post("/api/pet/do/pulse", requireAuth, async (req, res) => {
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

app.post("/api/pet/do/test-all", requireAuth, async (req, res) => {
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

app.post("/api/pet/do/test-selected", requireAuth, async (req, res) => {
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
    const rows = await dbQuery("SELECT * FROM schedule_slots ORDER BY id");
    res.json({ slots: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// PUT /schedule — remplacer toutes les plages
app.put("/schedule", requireAuth, async (req, res) => {
  try {
    const slots = Array.isArray(req.body?.slots) ? req.body.slots : [];
    await dbQuery("DELETE FROM schedule_slots");
    for (const s of slots) {
      if (s.start && s.end) {
        await dbQuery("INSERT INTO schedule_slots (`start`, `end`) VALUES (?, ?)", [s.start, s.end]);
      }
    }
    res.json({ ok: true, slots });
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
app.post("/rfid", requireAuth, async (req, res) => {
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
app.patch("/rfid/:id", requireAuth, async (req, res) => {
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
app.delete("/rfid/:id", requireAuth, async (req, res) => {
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

// ─── DÉMARRAGE ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`adjudicator.js lancé sur le port ${PORT}`);
  console.log(`PET-DO: ${PET_DO_IP}:${PET_DO_PORT} (unit ${PET_DO_UNIT})`);
  console.log(`PET-DI: ${PET_DI_IP}:${PET_DI_PORT} (unit ${PET_DI_UNIT})`);
  startPolling();
});