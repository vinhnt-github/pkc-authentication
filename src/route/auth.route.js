var express = require("express");
var router = express.Router();
const controller = require("../controllers/auth.controller");

router.post("/auth/login", controller.signin);
router.post("/auth/signup", controller.signup);
router.post("/auth/refreshtoken", controller.refreshToken);

module.exports = router;
