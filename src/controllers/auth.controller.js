const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const config = require("../config/auth.config");
const RefreshToken = require("../models/refreshToken.model");
const User = require("../models/user.model");
const { generateJWT } = require("../utils/auth");

exports.signup = async (req, res) => {
  try {
    const { username, password } = req.body;
    const userAlreadyExists = await User.find({ username });

    if (userAlreadyExists) {
      return res.status(400).json({
        message: "Username or email already exists",
      });
    }

    const newUser = {
      id: uuidv4(),
      username: username,
      password: bcrypt.hashSync(password, 8),
    };

    const userRecord = await User.create(newUser);

    return res.status(201).json({ user: userRecord });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "There are some error occurred!", error });
  }
};

exports.signin = async (req, res) => {
  const { username, password } = req.body;
  const user = await User.find({ username });
  if (!user) {
    return res.status(401).send({ message: "Invalid username or password!" });
  }

  const passwordIsValid = bcrypt.compareSync(password, user.password);

  if (!passwordIsValid) {
    return res.status(401).send({
      accessToken: null,
      message: "Invalid username or password!",
    });
  }

  const accessToken = generateJWT(
    user.id,
    config.access_secret,
    config.jwtExpiration
  );
  const refreshToken = generateJWT(
    user.id,
    config.refresh_secret,
    config.jwtRefreshExpiration
  );

  await RefreshToken.insertToken(refreshToken);

  return res.json({
    accessToken,
    refreshToken,
  });
};

exports.refreshToken = async (req, res) => {
  const { refreshtoken } = req.body;

  if (!refreshtoken) {
    return res.status(204);
  }
  try {
    const refreshTokenInDB = await RefreshToken.find(refreshtoken);

    if (!refreshTokenInDB) {
      return res.status(401).send({ message: "Unauthorized!" });
    }

    try {
      const decodedToken = jwt.verify(
        refreshTokenInDB.token,
        config.refresh_secret
      );
      const { userId } = decodedToken;
      const user = await User.find({ id: userId });

      if (!user) {
        await clearTokens(req, res);
        const error = createError("Invalid credentials", 401);
        throw error;
      }

      const accessToken = generateJWT(
        user.id,
        config.access_secret,
        config.jwtExpiration
      );
      return res.status(200).json({
        accessToken,
        expiresAt: new Date(Date.now() + config.jwtExpiration),
      });
    } catch (error) {
      throw error;
    }
  } catch (error) {
    return res
      .status(500)
      .send({ message: "There are some error occurred!", error });
  }
};
