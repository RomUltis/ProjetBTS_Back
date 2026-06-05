const { DI_MAP } = require("../config/maps");

/*
 * DiPoller — lecture des entrées (PET-7050) POUR AFFICHAGE UNIQUEMENT.
 *
 * Depuis la refonte, la détection d'intrusion et le déclenchement de l'alarme
 * sont gérés par l'application C++. Ce poller ne décide donc plus rien : il se
 * contente de rafraîchir l'état des capteurs pour le dashboard (panneau DI) et
 * pour le pré-contrôle « portes ouvertes » avant un armement.
 */
class DiPoller {
  constructor({ petDI, config }) {
    this.petDI = petDI;
    this.pollMs = config.diPollMs;

    this.currentDIState = {};
    this._interval = null;
  }

  get current() {
    return this.currentDIState;
  }

  async pollDI() {
    try {
      const bits = await this.petDI.readDiscreteInputs(0, 18);
      for (const di of DI_MAP) {
        const rawVal = !!bits[di.ch];
        // Contacts NF inversés : true = état "en alerte" (porte ouverte / mouvement)
        this.currentDIState[di.ch] = di.inverted ? !rawVal : rawVal;
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
    console.log(`Lecture DI (affichage) démarrée (${this.pollMs}ms)`);
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
