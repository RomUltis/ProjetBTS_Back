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

//CONFIG
const PORT = Number(process.env.PORT);
const JWT_SECRET = process.env.JWT_SECRET;

// MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// PET-7067 (Modbus/TCP)
const PET_IP = process.env.PET_IP;
const PET_PORT = Number(process.env.PET_PORT || 502);
const PET_UNIT = Number(process.env.PET_UNIT || 1);

// Limites sécurité
const PULSE_MS_DEFAULT = 1000;
const PULSE_MS_MIN = 100;
const PULSE_MS_MAX = 3000;
const TEST_DELAY_DEFAULT = 1200;

db.connect((err) => {
  if (err) {
    console.error("Erreur connexion MySQL:", err);
    process.exit(1);
  }
  console.log("Connecté à MySQL");
});

// Auth
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

// Register
app.post("/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Données manquantes" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const role = "user";

  db.query(
    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
    [username, hashedPassword, role],
    (err) => {
      if (err) {
        console.error("Erreur inscription:", err);
        return res.status(500).json({
          success: false,
          message: "Nom d'utilisateur déjà utilisé (ou erreur DB)",
        });
      }
      return res.json({ success: true, message: "Compte créé" });
    }
  );
});

// Login
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
      const ok = bcrypt.compareSync(password, user.password_hash);
      if (!ok) {
        return res.status(401).json({ success: false, message: "Identifiants incorrects" });
      }

      const token = jwt.sign(
        { id: user.id, role: user.role },
        JWT_SECRET,
        { expiresIn: "2h" }
      );

      return res.json({
        success: true,
        role: user.role,
        userId: user.id,
        token,
      });
    }
  );
});

// PET-7067 Modbus/TCP
const pet = new ModbusRTU();
let petConnecting = null;

async function petConnect() {
  if (pet.isOpen) return;

  if (!petConnecting) {
    petConnecting = (async () => {
      await pet.connectTCP(PET_IP, { port: PET_PORT });
      pet.setID(PET_UNIT);
      pet.setTimeout(1500);
      console.log(`PET connecté: ${PET_IP}:${PET_PORT} (unit ${PET_UNIT})`);
    })().finally(() => {
      petConnecting = null;
    });
  }

  await petConnecting;
}

async function petWriteCoil(channel, value) {
  await petConnect();
  // coil 0..7 = DO0..DO7
  await pet.writeCoil(channel, !!value);
}

async function petPulseCoil(channel, ms) {
  await petWriteCoil(channel, true);
  setTimeout(async () => {
    try {
      await petWriteCoil(channel, false);
    } catch (e) {
      console.error(`PET OFF failed (DO${channel}):`, e?.message || e);
    }
  }, ms);
}

function clampMs(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n)) return PULSE_MS_DEFAULT;
  return Math.min(PULSE_MS_MAX, Math.max(PULSE_MS_MIN, n));
}

// API PET

// simple ping
app.get("/api/ping", (req, res) => res.json({ ok: true, msg: "adjudicator up" }));

// Pulse 1 relais (DO0..DO7), 1s par défaut
// body: { channel: 3, ms: 1000 }
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
    console.error("/api/pet/do/pulse:", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Test tous les relais DO0..DO7 (1s chacun) en séquence
// body: { ms: 1000, delay: 1200 }
app.post("/api/pet/do/test-all", requireAuth, async (req, res) => {
  try {
    const ms = clampMs(req.body?.ms ?? PULSE_MS_DEFAULT);
    const delay = Math.min(5000, Math.max(200, Number(req.body?.delay ?? TEST_DELAY_DEFAULT)));
    (async () => {
      for (let ch = 0; ch <= 7; ch++) {
        try {
          await petPulseCoil(ch, ms);
        } catch (e) {
          console.error(`Test DO${ch} failed:`, e?.message || e);
        }
        await new Promise((r) => setTimeout(r, delay));
      }
    })();

    return res.json({ ok: true, action: "test_all", ms, delay });
  } catch (e) {
    console.error("/api/pet/do/test-all:", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 adjudicator.js lancé sur le port ${PORT}`);
  console.log(`➡️ PET: ${PET_IP}:${PET_PORT} (unit ${PET_UNIT})`);
});
