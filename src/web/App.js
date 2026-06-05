const express = require("express");
const cors = require("cors");

const Config = require("../config/Config");
const Database = require("../db/Database");
const AuthService = require("../auth/AuthService");
const { makeAuthMiddleware } = require("../auth/authMiddleware");
const ModbusDevice = require("../hardware/ModbusDevice");
const CameraRegistry = require("../camera/CameraRegistry");
const SurveillanceClient = require("../surveillance/SurveillanceClient");
const AlarmService = require("../alarm/AlarmService");
const HlsManager = require("../camera/HlsManager");
const RecordingManager = require("../camera/RecordingManager");
const DiPoller = require("../alarm/DiPoller");
const ScheduleService = require("../alarm/ScheduleService");
const RfidService = require("../rfid/RfidService");

const featureRoutes = require("./routes/featureRoutes");
const authRoutes = require("./routes/authRoutes");
const alarmRoutes = require("./routes/alarmRoutes");
const surveillanceRoutes = require("./routes/surveillanceRoutes");
const diRoutes = require("./routes/diRoutes");
const doRoutes = require("./routes/doRoutes");
const scheduleRoutes = require("./routes/scheduleRoutes");
const userRoutes = require("./routes/userRoutes");
const rfidRoutes = require("./routes/rfidRoutes");
const camRoutes = require("./routes/camRoutes");

class App {
  constructor() {
    this.config = new Config();
    this.db = new Database(this.config);

    this.auth = new AuthService(this.config);
    this.mw = makeAuthMiddleware(this.auth);

    // PET-DO conservé uniquement pour les tests unitaires de relais (dashboard).
    // PET-DI conservé en lecture seule pour l'affichage des capteurs.
    this.petDO = new ModbusDevice({ ...this.config.petDO, name: "PET-DO" });
    this.petDI = new ModbusDevice({ ...this.config.petDI, name: "PET-DI" });
    this.cameras = new CameraRegistry(this.config);

    // Pont vers l'app C++ qui gère désormais toute l'alarme/surveillance.
    this.surveillance = new SurveillanceClient({ config: this.config });
    this.alarm = new AlarmService({ db: this.db, surveillance: this.surveillance, config: this.config, petDO: this.petDO });

    // Caméras : HLS réagit à 'armedChange' (RGPD) + enregistrement
    this.hls = new HlsManager({ config: this.config, cameras: this.cameras, getArmed: () => this.alarm.isArmed() });
    this.recordings = new RecordingManager({ config: this.config, cameras: this.cameras });

    // RGPD + arrêt de l'enregistrement de TOUTES les caméras au désarmement
    this.alarm.on("armedChange", (armed) => {
      this.hls.applyRgpdState(armed);
      if (!armed) {
        const stopped = this.recordings.stopAll({ onlyAuto: true });
        if (stopped.length) console.log(`🔓 Désarmement → ${stopped.length} enregistrement(s) alarme arrêté(s)`);
      }
    });

    // Intrusion signalée par le C++ (polling statut) → enregistre TOUTES les
    // caméras (chacune dans son dossier) jusqu'au désarmement manuel.
    this.surveillance.on("alarmActiveChange", (active) => {
      if (active) {
        const res = this.recordings.startAll("alarm");
        const ok = res.filter((r) => r.ok).length;
        console.log(`🚨 Intrusion C++ détectée → enregistrement démarré sur ${ok}/${res.length} caméra(s)`);
      }
    });

    this.diPoller = new DiPoller({ petDI: this.petDI, config: this.config });
    this.alarm.setDiStateProvider(() => this.diPoller.current);
    this.schedule = new ScheduleService({ db: this.db, alarm: this.alarm });

    this.rfid = new RfidService({ db: this.db });

    this.app = express();
    this._setupMiddleware();
    this._mountRoutes();
    this._setupShutdown();
  }

  _setupMiddleware() {
    this.app.use(express.json());
    this.app.use(cors());
    this.app.use(express.static("/var/www/html"));
  }

  _mountRoutes() {
    const { requireAuth, requireAuthFlexible, requireAdmin } = this.mw;

    this.app.use(featureRoutes({ config: this.config }));
    this.app.use(authRoutes({ db: this.db, authService: this.auth }));
    this.app.use(alarmRoutes({ alarm: this.alarm, requireAuth, requireAdmin }));
    this.app.use(surveillanceRoutes({ recordings: this.recordings, cameras: this.cameras, config: this.config }));
    this.app.use(diRoutes({ diPoller: this.diPoller, alarm: this.alarm, db: this.db, requireAuth }));
    this.app.use(doRoutes({ petDO: this.petDO, config: this.config, requireAuth, requireAdmin }));
    this.app.use(scheduleRoutes({ scheduleService: this.schedule, db: this.db, requireAuth, requireAdmin }));
    this.app.use(userRoutes({ db: this.db, requireAuth, requireAdmin }));
    this.app.use(rfidRoutes({ rfid: this.rfid, requireAuth, requireAdmin }));
    this.app.use(camRoutes({
      cameras: this.cameras, hls: this.hls, recordings: this.recordings,
      alarm: this.alarm, config: this.config,
      requireAuth, requireAuthFlexible, requireAdmin,
    }));
  }

  _setupShutdown() {
    const gracefulShutdown = (signal) => {
      console.log(`\n[HLS] Signal ${signal} reçu, arrêt des flux FFmpeg…`);
      this.surveillance.stopPolling();
      this.hls.stopAll();
      setTimeout(() => process.exit(0), 1000);
    };
    process.on("SIGINT", () => gracefulShutdown("SIGINT"));
    process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  }

  start() {
    this.db.connect().catch(() => process.exit(1));

    this.app.listen(this.config.PORT, async () => {
      console.log(`adjudicator.js lancé sur le port ${this.config.PORT}`);
      console.log(`Centrale C++ (surveillance/alarme) : ${this.config.surveillance.baseUrl}`);
      console.log(`PET-DO (tests relais) : ${this.config.petDO.ip}:${this.config.petDO.port} (unit ${this.config.petDO.unit})`);
      console.log(`PET-DI (affichage)    : ${this.config.petDI.ip}:${this.config.petDI.port} (unit ${this.config.petDI.unit})`);
      console.log(`Caméras configurées : ${this.cameras.length} (alarme → ${this.cameras.alarmRecCam})`);
      this.cameras.cameras.forEach((c) => console.log(`  - ${c.id} : ${c.name} (${c.type})`));

      if (this.config.rgpdCamsOnlyWhenArmed) {
        console.log(`🛡 RGPD : caméras désactivées quand l'alarme est désarmée (conformité art. 5.1.c)`);
      }

      // Lit l'état réel auprès du C++ avant de décider du démarrage des flux (RGPD)
      try {
        await this.surveillance.fetchStatus();
        console.log(`État alarme au boot (C++) : ${this.alarm.isArmed() ? "ARMÉE" : "désarmée"}`);
      } catch (e) {
        console.error("Centrale C++ injoignable au boot :", e.message);
      }

      if (this.config.rgpdCamsOnlyWhenArmed) {
        this.hls.purgeSegments();
      }

      this.surveillance.startPolling();
      this.diPoller.start();
      this.schedule.start();
      this.hls.startAll();
    });
  }
}

module.exports = App;
