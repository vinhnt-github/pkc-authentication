const { userData } = require("../data");

module.exports = {
  find: async (query) => {
    const key = Object.keys(query)[0];
    return query[key] === userData[key] ? userData : null;
  },
};
