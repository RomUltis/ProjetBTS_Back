const EventEmitter = require("events");

/*
 * SurveillanceClient
 * ------------------
 * Pont HTTP vers l'application C++ (AlarmCore / SurveillanceHttpApi).
 *
 * Depuis la refonte, TOUTE la surveillance et l'alarme sont gérées par le C++ :
 *   - le back ne fait que lui relayer arm()/disarm() ;
 *   - il sonde périodiquement GET /surveillance/status pour connaître l'état
 *     réel (armé / alarme en cours / capteurs) et le refléter dans le dashboard
 *     + piloter le RGPD des caméras.
 *
 * Le démarrage des enregistrements, lui, est poussé par le C++ (webhook
 * /api/surveillance/event) : « le C++ dit au back d'enregistrer ».
 *
 * Évènements émis :
 *   - 'armedChange'(armed)        : l'état armé a changé (écouté par HlsManager)
 *   - 'alarmActiveChange'(active) : une alarme C++ démarre / s'arrête
 *   - 'reachableChange'(ok)       : la connexion à l'app C++ est (re)devenue ok/ko
 */
class SurveillanceClient extends EventEmitter {
  constructor({ config }) {
    super();
    this.baseUrl = config.surveillance.baseUrl;
    this.token = config.surveillance.token;
    this.pollMs = config.surveillance.pollMs;
    this.timeoutMs = config.surveillance.timeoutMs;

    this._armed = false;
    this._alarmActive = false;
    this._doorOpen = false;
    this._windowOpen = false;
    this._reachable = null; // null = jamais joint encore
    this._interval = null;
  }

  isArmed() { return this._armed; }
  isAlarmActive() { return this._alarmActive; }
  isReachable() { return this._reachable === true; }

  status() {
    return {
      armed: this._armed,
      alarm_active: this._alarmActive,
      door_open: this._doorOpen,
      window_open: this._windowOpen,
      reachable: this._reachable === true,
    };
  }

  // Requête HTTP bas niveau (fetch natif Node 18+) avec timeout.
  async _request(method, path) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = {};
      if (this.token) headers["x-surveillance-token"] = this.token;
      const res = await fetch(`${this.baseUrl}${path}`, { method, headers, signal: controller.signal });
      const text = await res.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch { /* réponse non-JSON */ }
      if (!res.ok) throw new Error(`HTTP ${res.status} ${path}`);
      this._setReachable(true);
      return json || {};
    } catch (e) {
      this._setReachable(false);
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  _setReachable(ok) {
    if (this._reachable !== ok) {
      this._reachable = ok;
      this.emit("reachableChange", ok);
      console.log(ok ? "✅ App C++ surveillance joignable" : "⚠️  App C++ surveillance injoignable");
    }
  }

  // Met à jour le cache local depuis un objet de statut C++ et émet les events.
  _applyStatus(s) {
    if (!s || typeof s !== "object") return;
    const prevArmed = this._armed;
    const prevAlarm = this._alarmActive;

    if (typeof s.armed === "boolean") this._armed = s.armed;
    if (typeof s.alarm_active === "boolean") this._alarmActive = s.alarm_active;
    if (typeof s.door_open === "boolean") this._doorOpen = s.door_open;
    if (typeof s.window_open === "boolean") this._windowOpen = s.window_open;

    if (prevArmed !== this._armed) this.emit("armedChange", this._armed);
    if (prevAlarm !== this._alarmActive) this.emit("alarmActiveChange", this._alarmActive);
  }

  async arm() {
    const s = await this._request("POST", "/surveillance/arm");
    this._applyStatus(s);
    return this.status();
  }

  async disarm() {
    const s = await this._request("POST", "/surveillance/disarm");
    this._applyStatus(s);
    return this.status();
  }

  async fetchStatus() {
    const s = await this._request("GET", "/surveillance/status");
    this._applyStatus(s);
    return this.status();
  }

  startPolling() {
    if (this._interval) return;
    const tick = async () => {
      try { await this.fetchStatus(); }
      catch (e) { /* injoignable : déjà signalé via reachableChange */ }
    };
    this._interval = setInterval(tick, this.pollMs);
    tick();
    console.log(`Surveillance C++ : polling ${this.baseUrl}/surveillance/status (${this.pollMs}ms)`);
  }

  stopPolling() {
    if (this._interval) { clearInterval(this._interval); this._interval = null; }
  }
}

module.exports = SurveillanceClient;
