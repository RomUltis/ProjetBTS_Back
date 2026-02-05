require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = "fixmyit_secret";

console.log("NodeJS démarre avec le host : ", process.env.HOST);

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error("Erreur de connexion MySQL:", err);
        process.exit(1);
    }
    console.log("Connecté à MySQL");
});

// Inscription
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) 
        return res.status(400).json({ success: false, message: "Données manquantes" });

    const hashedPassword = bcrypt.hashSync(password, 10);

    // Ajout du rôle "user" par défaut lors de l'inscription
    const role = 'user';
    db.query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", [username, hashedPassword, role], (err, result) => {
        if (err) {
            console.error("Erreur lors de l'inscription:", err);
            return res.status(500).json({ success: false, message: "Nom d'utilisateur déjà utilisé" });
        }
        res.json({ success: true, message: "Compte créé avec succès" });
    });
});

// Connexion
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) 
        return res.status(400).json({ success: false, message: "Données manquantes" });

    db.query("SELECT id, password_hash, role FROM users WHERE username = ?", [username], (err, results) => {
        if (err || results.length === 0) {
            console.error("Erreur lors de la connexion:", err);
            return res.status(401).json({ success: false, message: "Identifiants incorrects" });
        }

        const user = results[0];
        if (!bcrypt.compareSync(password, user.password_hash)) 
            return res.status(401).json({ success: false, message: "Identifiants incorrects" });

        // Le token contient l'ID et le rôle de l'utilisateur
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "2h" });
        
        // Envoi du rôle et de l'ID utilisateur dans la réponse
        res.json({ 
            success: true, 
            role: user.role,
            userId: user.id, 
            token 
        });
    });
});

// Page de test pour vérifier si le serveur tourne
app.get('/', (req, res) => {
    res.send('Le serveur adjudicator fonctionne correctement.');
});

// Lancer le serveur
app.listen(3001, () => {
    console.log("🚀 Serveur adjudicator en cours d'exécution sur le port 3001");
});
