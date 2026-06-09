const { DI_MAP } = require("../config/maps");

/*
 * DiPoller — lecture des entrées (PET-7050).
 *
 * Rôle :
 *   1. rafraîchir l'état des capteurs pour le dashboard (panneau DI) ;
 *   2. DÉTECTER LES INTRUSIONS : quand le système est armé (état fourni par
 *      getArmed) et qu'un capteur passe en alerte (porte ouverte / mouvement),
 *      on appelle onIntrusion(di) → le back lance l'enregistrement + journalise.
 *
 *   Le C++ ne surveillant que 2 entrées fixes, c'est le back (qui lit les 6
 *   vrais capteurs avec zones/labels) qui pilote l'enregistrement vidéo.
 */
class DiPoller {
  constructor({ petDI, config, getArmed, onIntrusion }) {
    this.petDI = petDI;
    this.pollMs = config.diPollMs;
    this.getArmed = getArmed || (() => false);
    this.onIntrusion = onIntrusion || (() => {});

    this.currentDIState = {};
    this.lastDIState = {};
    this._interval = null;
  }

  get current() {
    return this.currentDIState;
  }

  async pollDI() {
    try {
      const bits = await this.petDI.readDiscreteInputs(0, 18);
      const armed = this.getArmed();
      for (const di of DI_MAP) {
        const rawVal = !!bits[di.ch];
        // Contacts NF inversés : true = état "en alerte" (porte ouverte / mouvement)
        const val = di.inverted ? !rawVal : rawVal;
        const prev = this.lastDIState[di.ch];
        this.currentDIState[di.ch] = val;

        // Intrusion : un capteur passe EN ALERTE (false → true) pendant que c'est armé.
        if (prev === false && val === true && armed) {
          this.onIntrusion(di);
        }
        this.lastDIState[di.ch] = val;
      }
    } catch (e) {
      console.error("pollDI error:", e?.message || e);
      if (this.petDI.isOpen) {
        this.petDI.close();
      }
    }
  }

  start() {
    if (this._interval) return;
    console.log(`Lecture DI + détection intrusion démarrée (${this.pollMs}ms)`);
    this._interval = setInterval(() => this.pollDI(), this.pollMs);
    this.pollDI();
  }

  currentStatus() {
    return DI_MAP.map((di) => ({
      ch: di.ch,
      zone: di.zone,
      label: di.label,
      type: di.type,
      value: !!this.currentDIState[di.ch],
    }));
  }

  async readMapped() {
    const bits = await this.petDI.readDiscreteInputs(0, 18);
    return DI_MAP.map((di) => {
      const rawVal = !!bits[di.ch];
      return {
        ch: di.ch,
        zone: di.zone,
        label: di.label,
        type: di.type,
        value: di.inverted ? !rawVal : rawVal,
      };
    });
  }
}

module.exports = DiPoller;
