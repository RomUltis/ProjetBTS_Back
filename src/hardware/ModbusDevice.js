const ModbusRTU = require("modbus-serial");

class ModbusDevice {
  constructor({ ip, port, unit, name }) {
    this.ip = ip;
    this.port = port;
    this.unit = unit;
    this.name = name;
    this.client = new ModbusRTU();
    this._connecting = null;
  }

  get isOpen() {
    return this.client.isOpen;
  }

  // Connexion à la demande, mutualisée entre appels concurrents
  async connect() {
    if (this.client.isOpen) return;
    if (!this._connecting) {
      this._connecting = (async () => {
        await this.client.connectTCP(this.ip, { port: this.port });
        this.client.setID(this.unit);
        this.client.setTimeout(1500);
        console.log(`${this.name} connecté: ${this.ip}:${this.port} (unit ${this.unit})`);
      })().finally(() => { this._connecting = null; });
    }
    await this._connecting;
  }

  async writeCoil(channel, value) {
    await this.connect();
    await this.client.writeCoil(channel, !!value);
  }

  // Active la sortie puis la coupe après ms (impulsion gâche / test relais)
  async pulseCoil(channel, ms) {
    await this.writeCoil(channel, true);
    setTimeout(async () => {
      try { await this.writeCoil(channel, false); }
      catch (e) { console.error(`${this.name} OFF failed (DO${channel}):`, e?.message || e); }
    }, ms);
  }

  async readDiscreteInputs(start, count) {
    await this.connect();
    const result = await this.client.readDiscreteInputs(start, count);
    return result.data;
  }

  close() {
    try { this.client.close(); } catch {}
  }
}

module.exports = ModbusDevice;
