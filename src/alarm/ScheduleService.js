class ScheduleService {
  constructor({ db, alarm }) {
    this.db = db;
    this.alarm = alarm;
    this._interval = null;
  }

  isInSchedule(slots) {
    if (!slots || slots.length === 0) return false;

    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    const current = `${hh}:${mm}`;

    for (const slot of slots) {
      if (!slot.start || !slot.end) continue;

      if (slot.start <= slot.end) {
        if (current >= slot.start && current < slot.end) return true;
      } else {
        // Plage qui traverse minuit (ex : 21:00 → 07:00)
        if (current >= slot.start || current < slot.end) return true;
      }
    }
    return false;
  }

  async loadSlots() {
    try {
      return await this.db.query("SELECT `id`, `start`, `end` FROM `schedule_slots` ORDER BY `id`");
    } catch (e) {
      console.error("loadScheduleSlots error:", e.message);
      return [];
    }
  }

  // Arme/désarme automatiquement selon l'heure courante.
  // L'armement réel est délégué à l'app C++ (via alarm.arm()/disarm()).
  async checkSchedule() {
    try {
      const slots = await this.loadSlots();
      const inSchedule = this.isInSchedule(slots);
      const armed = this.alarm.isArmed();

      const now = new Date();
      const hh = String(now.getHours()).padStart(2, "0");
      const mm = String(now.getMinutes()).padStart(2, "0");

      console.log(`⏰ Schedule check: ${hh}:${mm} | ${slots.length} plage(s) | inSchedule=${inSchedule} | armed=${armed} | armedBySchedule=${this.alarm.armedBySchedule}`);

      if (inSchedule && !armed) {
        const openDoors = this.alarm.openDoors();
        if (openDoors.length > 0) {
          console.log(`⏰ Schedule: dans la plage mais porte(s) ouverte(s) → armement impossible (${openDoors.map((d) => d.label).join(", ")})`);
          return;
        }

        await this.alarm.arm();
        this.alarm.armedBySchedule = true;
        console.log(`⏰ Schedule: ARMEMENT AUTOMATIQUE relayé au C++`);

      } else if (!inSchedule && armed && this.alarm.armedBySchedule) {
        // Ne pas désarmer si une alarme est en cours
        if (this.alarm.triggered) {
          console.log(`⏰ Schedule: fin de plage mais alarme en cours → on ne désarme PAS`);
          return;
        }

        await this.alarm.disarm();
        this.alarm.armedBySchedule = false;
        console.log(`⏰ Schedule: DÉSARMEMENT AUTOMATIQUE relayé au C++ (fin de plage, aucune détection)`);
      }
    } catch (e) {
      console.error("checkSchedule error:", e.message);
    }
  }

  // État courant pour la route GET /api/schedule/now (serveur C++)
  async now() {
    const slots = await this.loadSlots();
    const inSchedule = this.isInSchedule(slots);
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    return { in_schedule: inSchedule, current_time: `${hh}:${mm}`, slots };
  }

  start() {
    if (this._interval) return;
    this._interval = setInterval(() => this.checkSchedule(), 30000);
    this.checkSchedule();
  }
}

module.exports = ScheduleService;
