const { DI_MAP } = require("../config/maps");

class DiPoller {
  constructor({ petDI, alarm, config }) {
    this.petDI = petDI;
    this.alarm = alarm;
    this.pollMs = config.diPollMs;

    this.lastDIState = {};
    this.currentDIState = {};
    this._interval = null;
  }

  get current() {
    return this.currentDIState;
  }

  async pollDI() {
    try {
      await this.alarm.checkSirenTimeout();

      const bits = await this.petDI.readDiscreteInputs(0, 18);
      const config = await this.alarm.loadConfig();

      for (const di of DI_MAP) {
        const rawVal = !!bits[di.ch];
        // Contacts NF inversés : triggered = état "en alerte" (porte ouverte / mouvement)
        const triggered = di.inverted ? !rawVal : rawVal;
        const prev = this.lastDIState[di.ch];
        this.currentDIState[di.ch] = triggered;

        if (prev !== undefined && prev !== triggered) {
          console.log(`DI${di.ch} changé: ${prev} → ${triggered} (${di.label})`);
          const willTrigger = config.armed && triggered && !this.alarm.triggered;

          if (config.armed) {
            await this.alarm.logDIEvent(di.ch, triggered, willTrigger);
          }

          if (willTrigger) {
            await this.alarm.triggerAlarm(di.ch, config);
          }
        }

        this.lastDIState[di.ch] = triggered;
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
    console.log(`Polling DI démarré (${this.pollMs}ms)`);
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
