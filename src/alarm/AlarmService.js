const EventEmitter = require("events");
const { DI_MAP, DO_MAP } = require("../config/maps");

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

const BEEP_MS = 100;       // durée d'un bip (très court)
const BEEP_GAP_MS = 1000;  // silence entre les deux bips d'armement

/*
 * AlarmService — façade « alarme » du back.
 *
 * Depuis la refonte, l'alarme et la surveillance sont ENTIÈREMENT gérées par
 * l'application C++ (AlarmCore). Ce service ne fait plus que :
 *   1. relayer arm()/disarm() au SurveillanceClient (→ API HTTP C++) ;
 *   2. refléter l'état temps réel renvoyé par le C++ (armé / alarme en cours) ;
 *   3. conserver en base les préférences d'armement affichées par le dashboard
 *      (zones, sorties exclues, durée sirène). Ces champs sont désormais
 *      purement informatifs côté back : la logique réelle (sirène, flash,
 *      temporisation, détection) vit dans le C++.
 *
 * Il n'écrit plus aucun coil Modbus et ne déclenche plus aucune alarme.
 * Émet 'armedChange' (relayé depuis le C++) — écouté par HlsManager (RGPD).
 */
class AlarmService extends EventEmitter {
  constructor({ db, surveillance, config, petDO }) {
    super();
    this.db = db;
    this.surveillance = surveillance;
    this.config = config;
    this.petDO = petDO; // utilisé uniquement pour les bips sonores (retour utilisateur)

    this.armedBySchedule = false;
    this.beepEnabled = true;
    this._beeping = false;
    this._diStateProvider = () => ({});

    // L'état armé fait désormais autorité côté C++ : on se contente de relayer
    // ses transitions (poussées par le SurveillanceClient) au reste du back.
    this.surveillance.on("armedChange", (armed) => {
      if (!armed) this.armedBySchedule = false;
      this.emit("armedChange", armed);
    });
  }

  setDiStateProvider(fn) { this._diStateProvider = fn; }

  // ---- État (source de vérité = app C++) ----
  isArmed() { return this.surveillance.isArmed(); }
  get triggered() { return this.surveillance.isAlarmActive(); }
  get triggerInfo() {
    if (!this.surveillance.isAlarmActive()) return null;
    const s = this.surveillance.status();
    return {
      source: s.door_open ? "porte" : (s.window_open ? "fenetre" : "capteur"),
      door_open: s.door_open,
      window_open: s.window_open,
      time: new Date().toISOString(),
    };
  }

  // ---- Préférences (base) ----
  async loadConfig() {
    const defaults = { armed_zones: ["ciel1", "ciel2", "physique"], excluded_do: [0], siren_duration: 180 };
    try {
      const rows = await this.db.query("SELECT * FROM alarm_config WHERE id = 1");
      if (rows.length === 0) return { armed: this.surveillance.isArmed(), ...defaults };
      const r = rows[0];
      return {
        // l'état armé fait foi côté C++, pas la colonne en base
        armed: this.surveillance.isArmed(),
        armed_zones: typeof r.armed_zones === "string" ? JSON.parse(r.armed_zones) : r.armed_zones,
        excluded_do: typeof r.excluded_do === "string" ? JSON.parse(r.excluded_do) : r.excluded_do,
        siren_duration: r.siren_duration || 180,
      };
    } catch (e) {
      console.error("loadAlarmConfig error:", e.message);
      return { armed: this.surveillance.isArmed(), ...defaults };
    }
  }

  // Persiste uniquement les préférences (la colonne `armed` n'est plus pilotée ici).
  async saveConfig(cfg) {
    await this.db.query(
      "UPDATE alarm_config SET armed_zones=?, excluded_do=?, siren_duration=? WHERE id=1",
      [JSON.stringify(cfg.armed_zones), JSON.stringify(cfg.excluded_do), cfg.siren_duration]
    );
  }

  // ---- Délégation au C++ ----
  async arm() { return this.surveillance.arm(); }
  async disarm() { return this.surveillance.disarm(); }

  // Toutes les portes/fenêtres actuellement ouvertes (zone-agnostique).
  // La centrale C++ refuse l'armement dès qu'UNE ouverture est ouverte — on
  // aligne le back sur cette règle pour refuser localement et immédiatement,
  // sans dépendre de l'aller-retour vers le C++.
  openDoors() {
    const diState = this._diStateProvider() || {};
    return DI_MAP.filter((di) => di.type === "porte" && !!diState[di.ch]);
  }

  // ---- Bips sonores (retour utilisateur) ----
  // Le back pilote brièvement la/les sirène(s) via petDO pour signaler
  // l'armement (double bip) et le désarmement (simple bip). Chaque bip est
  // très court (BEEP_MS) ; les deux bips d'armement sont espacés de BEEP_GAP_MS.
  // À lancer SANS await (tâche de fond) pour ne pas retarder la réponse HTTP.
  beepArm() { return this._beep(2); }
  beepDisarm() { return this._beep(1); }

  async _beep(count) {
    if (!this.beepEnabled || !this.petDO || this._beeping) return;
    const sirens = DO_MAP.filter((d) => d.role === "sirene");
    if (sirens.length === 0) return;

    this._beeping = true;
    try {
      for (let i = 0; i < count; i++) {
        for (const d of sirens) { try { await this.petDO.writeCoil(d.ch, true); } catch {} }
        await delay(BEEP_MS);
        for (const d of sirens) { try { await this.petDO.writeCoil(d.ch, false); } catch {} }
        if (i < count - 1) await delay(BEEP_GAP_MS); // espacement entre les deux bips d'armement
      }
    } finally {
      this._beeping = false;
    }
  }
}

module.exports = AlarmService;
