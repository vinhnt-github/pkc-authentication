const jwt = require("jsonwebtoken");

exports.generateJWT = (userId, secret, expirationTime) => {
  return jwt.sign(
    {
      userId,
    },
    secret,
    { expiresIn: expirationTime }
  );
};
