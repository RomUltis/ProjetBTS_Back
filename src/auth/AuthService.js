const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

class AuthService {
  constructor(config) {
    this.jwtSecret = config.JWT_SECRET;
  }

  // Token valable 2h par défaut
  sign(payload, options = { expiresIn: "2h" }) {
    return jwt.sign(payload, this.jwtSecret, options);
  }

  verify(token) {
    return jwt.verify(token, this.jwtSecret);
  }

  hashPassword(password) {
    return bcrypt.hashSync(password, 10);
  }

  comparePassword(password, hash) {
    return bcrypt.compareSync(password, hash);
  }
}

module.exports = AuthService;
