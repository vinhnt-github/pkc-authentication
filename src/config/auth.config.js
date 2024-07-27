require("dotenv").config();

module.exports = {
  access_secret: process.env.SECRET_KEY,
  refresh_secret: process.env.REFRESH_KEY,
  // jwtExpiration: 3600,         // 1 hour
  // jwtRefreshExpiration: 86400, // 24 hours

  /* for test */
  jwtExpiration: 60, // 1 minute
  jwtRefreshExpiration: 1200, // 20 minutes
};
