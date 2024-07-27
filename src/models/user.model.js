const { userData } = require("../data");

module.exports = {
  find: async (query) => {
    const key = Object.keys(query)[0];
    return userData.find((user) => query[key] === user[key]);
  },
  create: async (user) => {
    userData.push(user);
    return user;
  },
};
