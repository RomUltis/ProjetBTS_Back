const express = require("express");

module.exports = function authRoutes({ db, authService }) {
  const router = express.Router();

  // Création de compte réservée aux administrateurs connectés
  router.post("/register", async (req, res) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Vous devez être connecté avec un compte administrateur pour créer un compte.",
      });
    }

    let decoded;
    try {
      decoded = authService.verify(token);
    } catch (err) {
      return res.status(403).json({ success: false, message: "Session invalide ou expirée." });
    }

    if (!decoded.role || decoded.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Accès refusé : seul un administrateur peut créer un compte.",
      });
    }

    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Données manquantes" });
    }

    const hashedPassword = authService.hashPassword(password);

    try {
      await db.query(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        [username, hashedPassword, "user"]
      );
      return res.json({ success: true, message: "Compte créé" });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Nom d'utilisateur déjà utilisé (ou erreur DB)",
      });
    }
  });

  router.post("/login", async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Données manquantes" });
    }
    try {
      const results = await db.query(
        "SELECT id, password_hash, role FROM users WHERE username = ?",
        [username]
      );
      if (!results || results.length === 0) {
        return res.status(401).json({ success: false, message: "Identifiants incorrects" });
      }
      const user = results[0];
      if (!authService.comparePassword(password, user.password_hash)) {
        return res.status(401).json({ success: false, message: "Identifiants incorrects" });
      }
      const token = authService.sign({ id: user.id, role: user.role });
      return res.json({ success: true, role: user.role, userId: user.id, token });
    } catch (err) {
      return res.status(401).json({ success: false, message: "Identifiants incorrects" });
    }
  });

  return router;
};
