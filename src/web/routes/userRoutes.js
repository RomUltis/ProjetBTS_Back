const express = require("express");

module.exports = function userRoutes({ db, requireAuth, requireAdmin }) {
  const router = express.Router();

  router.get("/api/users", requireAuth, requireAdmin, async (req, res) => {
    try {
      const rows = await db.query("SELECT id, username, role FROM users ORDER BY id");
      res.json({ ok: true, users: rows });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.patch("/api/users/:id/role", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { role } = req.body || {};
      const userId = Number(req.params.id);

      if (!["admin", "user"].includes(role)) {
        return res.status(400).json({ ok: false, error: "Rôle invalide (admin ou user)" });
      }

      // On ne peut pas se rétrograder soi-même
      if (userId === req.user.id && role !== "admin") {
        return res.status(400).json({ ok: false, error: "Tu ne peux pas te rétrograder toi-même" });
      }

      await db.query("UPDATE users SET role = ? WHERE id = ?", [role, userId]);
      console.log(`[USERS] Rôle de user #${userId} changé → ${role}`);
      res.json({ ok: true, message: `Rôle mis à jour → ${role}` });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.delete("/api/users/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
      const userId = Number(req.params.id);

      // On ne peut pas supprimer son propre compte
      if (userId === req.user.id) {
        return res.status(400).json({ ok: false, error: "Tu ne peux pas supprimer ton propre compte" });
      }

      await db.query("DELETE FROM users WHERE id = ?", [userId]);
      console.log(`[USERS] User #${userId} supprimé`);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  return router;
};
