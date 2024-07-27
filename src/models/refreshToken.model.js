const { tokens } = require("../data");

exports.insertToken = async (token) => {
  // save refresh token to database
  /*
      sql sample
      `
        INSERT INTO RefreshToken (token)
        VALUES (${_token});
      `
    */
  tokens.push({
    token: token,
  });

  //insert success return new refresh token record
  // sample
  const newRefreshToken = {
    token: token,
  };

  return newRefreshToken;
};
exports.find = async (token) => {
  // query refresh token in database

  const tokenRecord = tokens.find((tk) => tk.token === token);

  return tokenRecord;
};
