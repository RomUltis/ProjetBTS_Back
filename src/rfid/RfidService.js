class RfidService {
  constructor({ db, alarm, petDO }) {
    this.db = db;
    this.alarm = alarm;
    this.petDO = petDO;

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

  // Vérification d'un badge (appelée par le serveur C++), insensible à la casse
  async check(uid, { log = false } = {}) {
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

  // Scan matériel : bascule l'alarme selon le badge. Recherche par uid exact.
  async scan({ card_id, raw_hex, wiegand_type }) {
    console.log(`[RFID] Scan reçu: card_id=${card_id}, raw=${raw_hex}, type=W${wiegand_type}`);

    if (this.enrollMode.active && Date.now() < this.enrollMode.expiresAt) {
      console.log(`[RFID] Mode enrollment → badge capturé: ${card_id}`);
      this.enrollMode.detectedUid = card_id;
      this.enrollMode.active = false;
      return { ok: true, enrollment: true, message: "Badge capturé pour enrollment" };
    }
    if (this.enrollMode.active && Date.now() >= this.enrollMode.expiresAt) {
      this.enrollMode.active = false;
      this.enrollMode.detectedUid = null;
    }

    const rows = await this.db.query(
      "SELECT * FROM rfid_badges WHERE uid = ? LIMIT 1",
      [card_id]
    );

    if (rows.length === 0) {
      console.log(`[RFID] Badge inconnu: ${card_id}`);
      try {
        await this.db.query(
          "INSERT INTO di_events (channel, zone, label, old_val, new_val, triggered) VALUES (?, ?, ?, ?, ?, ?)",
          [-1, "rfid", `Badge inconnu: ${card_id}`, 0, 1, 0]
        );
      } catch (e) { }
      return { ok: true, authorized: false, message: "Badge inconnu" };
    }

    const badge = rows[0];
    if (!badge.enabled) {
      console.log(`[RFID] Badge désactivé: ${card_id} (${badge.owner})`);
      return { ok: true, authorized: false, message: "Badge désactivé" };
    }

    console.log(`[RFID] ✓ Accès autorisé: ${badge.owner} (${card_id})`);

    const config = await this.alarm.loadConfig();
    let newArmedState;
    let alarmAction;

    if (config.armed) {
      config.armed = false;
      this.alarm.armedBySchedule = false;
      await this.alarm.saveConfig(config);
      if (this.alarm.triggered) {
        await this.alarm.disarm();
      } else {
        this.alarm.triggered = false;
        this.alarm.triggerInfo = null;
        // Pas d'alarme en cours : ouvrir la gâche soi-même (disarm() ne sera pas appelé)
        try { await this.petDO.pulseCoil(0, 3000); } catch {}
        console.log("[RFID] 🔓 Gâche ouverte (désarmement par badge)");
      }
      newArmedState = false;
      alarmAction = "disarmed";
      console.log(`[RFID] 🔓 Alarme DÉSARMÉE par ${badge.owner}`);

      if (this.alarm.beepEnabled) {
        await this.alarm.beepDisarm();
        console.log(`[RFID] 🔔 Bip désarmement`);
      }
    } else {
      const openDoors = this.alarm.findOpenDoors(config.armed_zones);
      if (openDoors.length > 0) {
        const names = openDoors.map((d) => d.label).join(", ");
        console.log(`[RFID] ⚠ Armement impossible — portes ouvertes: ${names}`);

        try {
          await this.db.query(
            "INSERT INTO di_events (channel, zone, label, old_val, new_val, triggered) VALUES (?, ?, ?, ?, ?, ?)",
            [-1, "rfid", `Armement refusé (portes ouvertes): ${badge.owner}`, 0, 1, 0]
          );
        } catch (e) { }

        return {
          ok: true,
          authorized: true,
          owner: badge.owner,
          alarm_action: "arm_failed",
          message: `Armement impossible — portes ouvertes: ${names}`,
        };
      }

      config.armed = true;
      this.alarm.armedBySchedule = false;
      await this.alarm.saveConfig(config);
      newArmedState = true;
      alarmAction = "armed";
      console.log(`[RFID] 🔒 Alarme ARMÉE par ${badge.owner}`);

      if (this.alarm.beepEnabled) {
        await this.alarm.beepArm();
        console.log(`[RFID] 🔔🔔 Double bip armement`);
      }
    }

    try {
      await this.db.query(
        "INSERT INTO di_events (channel, zone, label, old_val, new_val, triggered) VALUES (?, ?, ?, ?, ?, ?)",
        [-1, "rfid", `${alarmAction === "armed" ? "Armement" : "Désarmement"} par ${badge.owner} (${card_id})`, 0, 1, 0]
      );
    } catch (e) { }

    return {
      ok: true,
      authorized: true,
      owner: badge.owner,
      alarm_action: alarmAction,
      armed: newArmedState,
      message: alarmAction === "armed" ? "Alarme armée" : "Alarme désarmée",
    };
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
