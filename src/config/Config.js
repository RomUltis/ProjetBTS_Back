class Config {
  constructor(env = process.env) {
    require("dotenv").config();
    env = process.env;

    this.PORT = Number(env.PORT || 80);
    this.JWT_SECRET = env.JWT_SECRET;

    this.rfidEnabled = env.RFID_ENABLED !== "false";

    this.db = {
      host: env.DB_HOST,
      user: env.DB_USER,
      password: env.DB_PASS,
      database: env.DB_NAME,
    };

    // PET-7067 — sorties (DO)
    this.petDO = {
      ip: env.PET_DO_IP || env.PET_IP,
      port: Number(env.PET_DO_PORT || 502),
      unit: Number(env.PET_DO_UNIT || 1),
    };

    // PET-7050 — entrées (DI)
    this.petDI = {
      ip: env.PET_DI_IP,
      port: Number(env.PET_DI_PORT || 502),
      unit: Number(env.PET_DI_UNIT || 1),
    };
    this.diPollMs = Number(env.DI_POLL_MS || 1000);

    this.PULSE_MS_DEFAULT = 1000;
    this.PULSE_MS_MIN = 100;
    this.PULSE_MS_MAX = 3000;
    this.TEST_DELAY_DEFAULT = 1200;

    this.RTSP_URL = env.RTSP_URL || "";
    this.RECORDINGS_PATH = env.RECORDINGS_PATH || "/sftp/camciel1/upload";

    this.hls = {
      enable: (env.HLS_ENABLE || "true").toLowerCase() !== "false",
      outputPath: env.HLS_OUTPUT_PATH || "/var/lib/alarme/hls",
      segmentDuration: Number(env.HLS_SEGMENT_DURATION || 2),
      listSize: Number(env.HLS_LIST_SIZE || 4),
    };

    // Caméras actives uniquement quand l'alarme est armée (RGPD)
    this.rgpdCamsOnlyWhenArmed = (env.RGPD_CAMS_ONLY_WHEN_ARMED || "true").toLowerCase() !== "false";

    this.cameras = this._loadCameras(env);
    this.alarmRecCam = `cam${Number(env.ALARM_REC_CAM || 1)}`;
  }

  _loadCameras(env) {
    const cams = [];
    for (let i = 1; i <= 8; i++) {
      const main = env[`CAM${i}_RTSP_MAIN`];
      const sub = env[`CAM${i}_RTSP_SUB`];
      if (!main && !sub) continue;
      cams.push({
        id: `cam${i}`,
        index: i,
        name: env[`CAM${i}_NAME`] || `Caméra ${i}`,
        type: env[`CAM${i}_TYPE`] || "generic",
        rtsp_main: main || "",
        rtsp_sub: sub || "",
        hls_main: `/cam/cam${i}/main/live.m3u8`,
        hls_sub: `/cam/cam${i}/sub/live.m3u8`,
        hlsMode: (env[`CAM${i}_HLS_MODE`] || "copy").toLowerCase(),
      });
    }
    // Ancien setup : une seule cam via RTSP_URL
    if (!cams.length && this.RTSP_URL) {
      cams.push({
        id: "cam1", index: 1, name: "Caméra principale", type: "dahua",
        rtsp_main: this.RTSP_URL, rtsp_sub: "",
        hls_main: "/cam/main/live.m3u8", hls_sub: "/cam/sub/live.m3u8",
        hlsMode: (env.CAM1_HLS_MODE || "copy").toLowerCase(),
      });
    }
    return cams;
  }

  clampPulseMs(ms) {
    const n = Number(ms);
    if (!Number.isFinite(n)) return this.PULSE_MS_DEFAULT;
    return Math.min(this.PULSE_MS_MAX, Math.max(this.PULSE_MS_MIN, n));
  }
}

module.exports = Config;
