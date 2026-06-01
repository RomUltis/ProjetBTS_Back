const EventEmitter = require("events");
const { DI_MAP, DO_MAP } = require("../config/maps");

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// Source de vérité de l'état "armé". Émet 'armedChange' -> écouté par HlsManager
// pour démarrer/couper les caméras (conformité RGPD).
class AlarmService extends EventEmitter {
  constructor({ db, petDO, config }) {
    super();
    this.db = db;
    this.petDO = petDO;
    this.config = config;

    this._armed = false;
    this.triggered = false;
    this.triggerInfo = null;
    this.armedBySchedule = false;
    this.beepEnabled = true;
    this._sirenActiveUntil = 0;
    this._sirenChannelsActive = [];

    this.recordingManager = null;
    this._diStateProvider = () => ({});
  }

  setRecordingManager(rm) { this.recordingManager = rm; }
  setDiStateProvider(fn) { this._diStateProvider = fn; }

  isArmed() { return this._armed; }
  // Initialise le cache au boot sans émettre d'event (pas d'effet RGPD)
  initArmedCache(value) { this._armed = !!value; }

  async loadConfig() {
    try {
      const rows = await this.db.query("SELECT * FROM alarm_config WHERE id = 1");
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

  async saveConfig(cfg) {
    const wasArmed = this._armed;
    const willBeArmed = !!cfg.armed;

    await this.db.query(
      "UPDATE alarm_config SET armed=?, armed_zones=?, excluded_do=?, siren_duration=? WHERE id=1",
      [cfg.armed ? 1 : 0, JSON.stringify(cfg.armed_zones), JSON.stringify(cfg.excluded_do), cfg.siren_duration]
    );

    this._armed = willBeArmed;
    if (wasArmed !== willBeArmed) this.emit("armedChange", willBeArmed);
  }

  // Portes/fenêtres ouvertes dans les zones armées (empêche l'armement)
  findOpenDoors(armedZones) {
    const diState = this._diStateProvider() || {};
    return DI_MAP.filter((di) => {
      if (di.type !== "porte") return false;
      const diZones = di.zone.split(",").map((z) => z.trim());
      const inArmedZone = diZones.some((z) => armedZones.includes(z));
      if (!inArmedZone) return false;
      return !!diState[di.ch];
    });
  }

  async logDIEvent(ch, value, triggered) {
    const diInfo = DI_MAP.find((d) => d.ch === ch) || { zone: "?", label: `DI${ch}` };
    try {
      await this.db.query(
        "INSERT INTO di_events (channel, zone, label, value, triggered) VALUES (?, ?, ?, ?, ?)",
        [ch, diInfo.zone, diInfo.label, value ? 1 : 0, triggered ? 1 : 0]
      );
    } catch (e) {
      console.error("logDIEvent error:", e.message);
    }
  }

  // Déclenche l'alarme : active toutes les sorties non exclues + enregistrement
  async triggerAlarm(diChannel, config) {
    const diInfo = DI_MAP.find((d) => d.ch === diChannel);
    if (!diInfo) return;

    const diZones = diInfo.zone.split(",").map((z) => z.trim());
    const triggerZones = diZones.filter((z) => config.armed_zones.includes(z));
    if (triggerZones.length === 0) return;

    this.triggered = true;
    this.triggerInfo = {
      diChannel,
      diLabel: diInfo.label,
      zones: triggerZones,
      allArmedZones: config.armed_zones,
      time: new Date().toISOString(),
    };

    const sirenMs = (config.siren_duration || 180) * 1000;
    this._sirenActiveUntil = Date.now() + sirenMs;

    console.log(`🚨 ALARME DÉCLENCHÉE par DI${diChannel} (${diInfo.label}) — sirène: ${config.siren_duration}s — activation: TOUTES les zones (y compris non surveillées)`);

    const dosToActivate = DO_MAP.filter((d) => !config.excluded_do.includes(d.ch));

    this._sirenChannelsActive = [];
    for (const doItem of dosToActivate) {
      try {
        await this.petDO.writeCoil(doItem.ch, true);
        console.log(`  ✓ DO${doItem.ch} ON (${doItem.zone} — ${doItem.role})`);
        if (doItem.role === "sirene") this._sirenChannelsActive.push(doItem.ch);
      } catch (e) {
        console.error(`  ✗ DO${doItem.ch} ON failed:`, e?.message || e);
      }
    }

    if (this.recordingManager) this.recordingManager.start("alarm");
  }

  // Coupe les sirènes une fois le délai écoulé
  async checkSirenTimeout() {
    if (!this.triggered || this._sirenChannelsActive.length === 0) return;
    if (Date.now() < this._sirenActiveUntil) return;

    console.log(`⏱ Timeout sirène atteint — coupure des sirènes`);
    for (const ch of this._sirenChannelsActive) {
      try {
        await this.petDO.writeCoil(ch, false);
        console.log(`  ⏱ DO${ch} OFF (sirène — timeout)`);
      } catch (e) {
        console.error(`  ✗ DO${ch} OFF (sirène timeout) failed:`, e?.message || e);
      }
    }
    this._sirenChannelsActive = [];
  }

  async disarm() {
    this._sirenActiveUntil = 0;
    this._sirenChannelsActive = [];

    // Ouvre la gâche (DO0) pour permettre d'entrer
    try {
      await this.petDO.pulseCoil(0, 3000);
      console.log("🔓 Gâche ouverte (désarmement)");
    } catch (e) {
      console.error("Gâche (désarmement) failed:", e?.message || e);
    }

    // Coupe toutes les sorties sauf la gâche (qui vient d'être pulsée)
    for (const doItem of DO_MAP) {
      if (doItem.role === "gache") continue;
      try {
        await this.petDO.writeCoil(doItem.ch, false);
      } catch (e) {
        console.error(`Disarm DO${doItem.ch} OFF failed:`, e?.message || e);
      }
    }

    this.triggered = false;
    this.triggerInfo = null;

    if (this.recordingManager) {
      const autoRec = this.recordingManager.get(this.config.alarmRecCam);
      if (autoRec && autoRec.autoAlarm) {
        this.recordingManager.stop(this.config.alarmRecCam);
        console.log("🔓 Enregistrement alarme arrêté automatiquement");
      }
    }

    console.log("🔓 Alarme désarmée — tous les DO coupés");

    this._armed = false;
    this.emit("armedChange", false);
  }

  async beepArm() {
    const bipDOs = DO_MAP.filter((d) => d.role !== "gache");
    for (let bip = 0; bip < 2; bip++) {
      for (const doItem of bipDOs) { try { await this.petDO.writeCoil(doItem.ch, true); } catch {} }
      await delay(150);
      for (const doItem of bipDOs) { try { await this.petDO.writeCoil(doItem.ch, false); } catch {} }
      if (bip === 0) await delay(150);
    }
  }

  async beepDisarm() {
    const bipDOs = DO_MAP.filter((d) => d.role !== "gache");
    for (const doItem of bipDOs) { try { await this.petDO.writeCoil(doItem.ch, true); } catch {} }
    await delay(150);
    for (const doItem of bipDOs) { try { await this.petDO.writeCoil(doItem.ch, false); } catch {} }
  }
}

module.exports = AlarmService;
