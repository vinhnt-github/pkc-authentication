const express = require("express");
require("dotenv").config();
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

// TODO
/*==================================MODELs*==========================*/
const User = require("./src/models/user.model");
const RefreshToken = require("./src/models/refreshToken.model");
//TODO: end

// Auth config
const authConfig = {
  access_secret: process.env.SECRET_KEY,
  refresh_secret: process.env.REFRESH_KEY,
  jwtExpiration: process.env.JWT_EXPIRATION || "1d", // 1 day
  jwtRefreshExpiration: process.env.JWT_REFRESH_EXPIRATION || "7d", // 7 days
};

const app = express();

// parse requests of content-type - application/json
app.use(express.json());

/*==================================UTILS*==========================*/
const generateJWT = (userId, secret, expirationTime) => {
  return jwt.sign(
    {
      userId,
    },
    secret,
    { expiresIn: expirationTime }
  );
};

/*==================================MIDDLEWARE*==========================*/
const authMiddleware = {
  verifyToken: (req, res, next) => {
    let token = req.headers["x-access-token"];
    if (!token) {
      return res.status(403).send({ message: "No token provided!" });
    }

    jwt.verify(token, authConfig.access_secret, (err, decoded) => {
      if (err) {
        if (err instanceof jwt.TokenExpiredError) {
          return res
            .status(401)
            .send({ message: "Unauthorized! Access Token was expired!" });
        }

        return res.status(401).send({ message: "Unauthorized!" });
      }
      req.userId = decoded.id;
      next();
    });
  },
};

/*==================================ROUTES*==========================*/
app.get("/", (req, res) => {
  res.json({ message: "Welcome to bezkoder application." });
});

app.post("/auth/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    //TODO: replace by SQL
    const userAlreadyExists = await User.find({ username });
    //TODO: end

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

    //TODO: replace by SQL
    const userRecord = await User.create(newUser);
    //TODO: end

    return res.status(201).json({ user: userRecord });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "There are some error occurred!", error });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  //TODO: replace by SQL
  const user = await User.find({ username });
  //TODO: end

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
    authConfig.access_secret,
    authConfig.jwtExpiration
  );
  const refreshToken = generateJWT(
    user.id,
    authConfig.refresh_secret,
    authConfig.jwtRefreshExpiration
  );

  await RefreshToken.insertToken(refreshToken);

  return res.json({
    accessToken,
    refreshToken,
  });
});

app.post("/auth/refreshtoken", async (req, res) => {
  const { refreshtoken } = req.body;

  if (!refreshtoken) {
    return res.status(204);
  }
  try {
    //TODO: replace by SQL
    const refreshTokenInDB = await RefreshToken.find(refreshtoken);
    //TODO: end

    if (!refreshTokenInDB) {
      return res.status(401).send({ message: "Unauthorized!" });
    }

    try {
      const decodedToken = jwt.verify(
        refreshTokenInDB.token,
        authConfig.refresh_secret
      );
      const { userId } = decodedToken;

      //TODO: replace by SQL
      const user = await User.find({ id: userId });
      //TODO: end

      if (!user) {
        return res.status(401).send({ message: "Invalid credentials" });
      }

      const accessToken = generateJWT(
        user.id,
        authConfig.access_secret,
        authConfig.jwtExpiration
      );
      return res.status(200).json({
        accessToken,
        expiresAt: new Date(Date.now() + authConfig.jwtExpiration),
      });
    } catch (error) {
      throw error;
    }
  } catch (error) {
    return res
      .status(500)
      .send({ message: "There are some error occurred!", error });
  }
});

app.get("/protected", [authMiddleware.verifyToken], (req, res) => {
  return res.send("protected data");
});

const PORT = process.env.PORT || 7200;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
