class CameraRegistry {
  constructor(config) {
    this.cameras = config.cameras;
    this.alarmRecCam = config.alarmRecCam;
  }

  get length() {
    return this.cameras.length;
  }

  getCamById(id) {
    return this.cameras.find(c => c.id === id) || null;
  }

  // Infos publiques uniquement : jamais les URLs RTSP (qui contiennent les identifiants)
  publicList() {
    return this.cameras.map(c => ({
      id: c.id,
      index: c.index,
      name: c.name,
      type: c.type,
      hls_main: c.hls_main,
      hls_sub: c.hls_sub,
    }));
  }
}

module.exports = CameraRegistry;
