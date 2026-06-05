const express = require("express");

module.exports = function featureRoutes({ config }) {
  const router = express.Router();

  router.get("/api/ping", (req, res) => res.json({ ok: true, msg: "adjudicator up" }));

  router.get("/api/features", (req, res) => {
    res.json({
      rfidEnabled: config.rfidEnabled,
      armConfigEnabled: config.armConfigEnabled,
    });
  });

  return router;
};
