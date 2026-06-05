const mysql = require("mysql");

class Database {
  constructor(config) {
    this.connection = mysql.createConnection({
      host: config.db.host,
      user: config.db.user,
      password: config.db.password,
      database: config.db.database,
    });
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.connection.connect((err) => {
        if (err) {
          console.error("Erreur connexion MySQL:", err);
          return reject(err);
        }
        console.log("Connecté à MySQL");
        resolve();
      });
    });
  }

  query(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.connection.query(sql, params, (err, results) => {
        if (err) reject(err); else resolve(results);
      });
    });
  }
}

module.exports = Database;
