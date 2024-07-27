const express = require("express");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const authMiddleware = require("./src/middleware/auth.middleware");
const authRoute = require("./src/route/auth.route");

const app = express();

// parse requests of content-type - application/json
app.use(express.json());
app.use(cookieParser("MY SECRET"));

app.get("/", (req, res) => {
  res.json({ message: "Welcome to bezkoder application." });
});

app.use(authRoute);

app.get("/protected", [authMiddleware.verifyToken], (req, res) => {
  return res.send("protected data");
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
