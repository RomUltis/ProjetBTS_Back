/*
 * RfidService — gestion et vérification des badges.
 *
 * Depuis la refonte, le contrôle d'accès RFID (badge → armement/désarmement,
 * ouverture de la gâche) est géré par l'application C++. Le back ne fait plus
 * que :
 *   - vérifier un badge à la demande du C++ (GET/POST /api/rfid/check) ;
 *   - gérer la liste des badges (CRUD côté dashboard) ;
 *   - l'enrôlement : capturer l'UID d'un nouveau badge. Comme les scans
 *     matériels arrivent maintenant au C++, c'est la requête de vérification
 *     envoyée par le C++ qui sert à capturer l'UID quand le mode est actif.
 *
 * Ce service ne touche plus ni à l'alarme ni au Modbus (gâche).
 */
class RfidService {
  constructor({ db }) {
    this.db = db;

    this.enrollMode = {
      active: false,
      startedAt: 0,
      expiresAt: 0,
      detectedUid: null,
    };
  }

  normalizeUid(uid) {
    return String(uid || "").trim().toUpperCase();
  }

  // Vérification d'un badge (appelée par l'app C++), insensible à la casse.
  // Si le mode enrollment est actif, l'UID présenté est capturé au passage.
  async check(uid, { log = false } = {}) {
    this._captureForEnroll(uid);

    const rows = await this.db.query(
      "SELECT * FROM rfid_badges WHERE UPPER(uid) = ? LIMIT 1",
      [uid]
    );

    if (rows.length === 0) {
      if (log) console.log(`[RFID C++] Badge inconnu: ${uid}`);
      return { ok: true, authorized: false, uid, message: "Badge inconnu" };
    }

    const badge = rows[0];
    if (!badge.enabled) {
      if (log) console.log(`[RFID C++] Badge désactivé: ${uid} (${badge.owner})`);
      return { ok: true, authorized: false, uid, owner: badge.owner, message: "Badge désactivé" };
    }

    if (log) console.log(`[RFID C++] Badge autorisé: ${uid} (${badge.owner})`);
    return { ok: true, authorized: true, uid, owner: badge.owner, message: "Badge autorisé" };
  }

  // Capture l'UID si une session d'enrollment est en cours (et non expirée).
  _captureForEnroll(uid) {
    if (!this.enrollMode.active) return;
    if (Date.now() >= this.enrollMode.expiresAt) {
      this.enrollMode.active = false;
      return;
    }
    console.log(`[RFID] Mode enrollment → badge capturé: ${uid}`);
    this.enrollMode.detectedUid = uid;
    this.enrollMode.active = false;
  }

  enrollStart() {
    const duration = 60000;
    this.enrollMode.active = true;
    this.enrollMode.startedAt = Date.now();
    this.enrollMode.expiresAt = Date.now() + duration;
    this.enrollMode.detectedUid = null;

    console.log("[RFID] Mode enrollment activé pour 60s");

    setTimeout(() => {
      if (this.enrollMode.active && Date.now() >= this.enrollMode.expiresAt) {
        this.enrollMode.active = false;
        console.log("[RFID] Mode enrollment expiré");
      }
    }, duration + 500);

    return { ok: true, message: "Mode enrollment activé", expiresAt: this.enrollMode.expiresAt };
  }

  enrollStatus() {
    if (this.enrollMode.active && Date.now() >= this.enrollMode.expiresAt) {
      this.enrollMode.active = false;
    }
    const remainingMs = this.enrollMode.active ? Math.max(0, this.enrollMode.expiresAt - Date.now()) : 0;
    return {
      ok: true,
      active: this.enrollMode.active,
      detected_uid: this.enrollMode.detectedUid,
      remaining_seconds: Math.ceil(remainingMs / 1000),
    };
  }

  enrollStop() {
    this.enrollMode.active = false;
    console.log("[RFID] Mode enrollment arrêté manuellement");
    return { ok: true, detected_uid: this.enrollMode.detectedUid };
  }

  async listBadges() {
    return this.db.query("SELECT * FROM rfid_badges ORDER BY created_at DESC");
  }

  // Laisse remonter l'erreur MySQL (la route traduit ER_DUP_ENTRY en 409)
  async addBadge({ uid, owner, enabled }) {
    await this.db.query(
      "INSERT INTO rfid_badges (uid, owner, enabled) VALUES (?, ?, ?)",
      [uid, owner || "", enabled !== undefined ? (enabled ? 1 : 0) : 1]
    );
  }

  // id = entier (colonne id) ou uid
  async toggleBadge(id, enabled) {
    const isNum = /^\d+$/.test(id);
    if (isNum) {
      await this.db.query("UPDATE rfid_badges SET enabled=? WHERE id=?", [enabled ? 1 : 0, Number(id)]);
    } else {
      await this.db.query("UPDATE rfid_badges SET enabled=? WHERE uid=?", [enabled ? 1 : 0, id]);
    }
  }

  async removeBadge(id) {
    const isNum = /^\d+$/.test(id);
    if (isNum) {
      await this.db.query("DELETE FROM rfid_badges WHERE id=?", [Number(id)]);
    } else {
      await this.db.query("DELETE FROM rfid_badges WHERE uid=?", [id]);
    }
  }
}

module.exports = RfidService;
