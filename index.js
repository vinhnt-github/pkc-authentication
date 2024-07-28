const express = require("express");
require("dotenv").config();
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cron = require("node-cron");
const axios = require("axios");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const ms = require("ms");

// TODO
/*==================================MODELs*==========================*/
const User = require("./src/models/user.model");
const RefreshToken = require("./src/models/refreshToken.model");
//TODO: end

/*==================================VARIBALES*==========================*/
let currentUser;
const saveCurrentUser = (user) => {
  currentUser = user;
};
const resetCurrentUser = () => {
  currentUser = undefined;
};

let external_access_token;
const saveExternalAccessToken = (token) => {
  external_access_token = token;
};
const resetExternalAccessToken = () => {
  external_access_token = undefined;
};

/*==================================CONFIG*==========================*/
const authConfig = {
  access_secret: process.env.SECRET_KEY,
  refresh_secret: process.env.REFRESH_KEY,
  jwtExpiration: process.env.JWT_EXPIRATION || "1d", // 1 day
  jwtRefreshExpiration: process.env.JWT_REFRESH_EXPIRATION || "7d", // 7 days
};
const UNCALL_EXTERNAl_AUTH_TIME =
  process.env.UNCALL_EXTERNAl_AUTH_TIME || 30 * 60 * 1000; // 30 minutes;

const corsOptions = {
  origin: "*",
  credentials: true,
};

const app = express();

app.use(cors(corsOptions));
app.use(cookieParser());

// parse requests of content-type - application/json
app.use(express.json());
app.use(express.urlencoded({}));

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

const callExternalAuthApi = (currentUser) => {
  return (
    axios
      //TODO : mock external auth api
      .post("http://localhost:3001/auth", { ...currentUser })
      .then(function (response) {
        const { accessToken: externalAccessToken } = response.data;
        if (externalAccessToken) saveExternalAccessToken(externalAccessToken);
        console.log("externalAccessToken", externalAccessToken);
      })
      .catch(function (error) {
        resetExternalAccessToken();
        console.log(error);
      })
      .finally(function () {
        console.log(`call external auth at ${Date.now()}`);
      })
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
      req.userId = decoded.userId;
      next();
    });
  },
};

let lastimeCall;
const logTimeMiddleware = (req, res, next) => {
  lastimeCall = Date.now();
  console.log(lastimeCall);
  next();
};
app.use(logTimeMiddleware);

/*==================================ROUTES*==========================*/

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

  // save current user
  saveCurrentUser({ username, password });

  callExternalAuthApi({ username, password });

  return res.json({
    accessToken,
    refreshToken,
  });
});

app.post("/auth/refreshtoken", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(403).send({ message: "No refresh token provided!" });
  }
  try {
    //TODO: replace by SQL
    const refreshTokenInDB = await RefreshToken.find(refreshToken);
    //TODO: end

    if (!refreshTokenInDB) {
      return res.status(401).send({ message: "Unauthorized!" });
    }

    try {
      const decodedToken = jwt.verify(
        refreshTokenInDB.token,
        authConfig.refresh_secret,
        (err, decoded) => {
          if (err) {
            if (err instanceof jwt.TokenExpiredError) {
              resetCurrentUser();
              return res
                .status(401)
                .send({ message: "Unauthorized! Access Token was expired!" });
            }

            return res.status(401).send({ message: "Unauthorized!" });
          }
          return decoded;
        }
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
        expiresAt: new Date(Date.now() + ms(authConfig.jwtExpiration)),
      });
    } catch (error) {
      throw error;
    }
  } catch (error) {
    resetCurrentUser();
    return res
      .status(500)
      .send({ message: "There are some error occurred!", error });
  }
});

app.post("/auth/logout", [authMiddleware.verifyToken], async (req, res) => {
  const { userId } = req;
  //TODO: Detele refereshToken theo UserId
  return res.json({
    message: "logout success",
  });
});

app.get("/protected", [authMiddleware.verifyToken], (req, res) => {
  return res.send("protected data");
});

const PORT = process.env.PORT || 7200;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});

const callExternalAuthJob = () => {
  if (!currentUser) {
    console.log("Not logged in");
    return;
  }
  if (!lastimeCall || Date.now() - lastimeCall > UNCALL_EXTERNAl_AUTH_TIME) {
    console.log("time exceeded");
    return;
  }

  callExternalAuthApi(currentUser);
};

// call every 1 minutes
cron.schedule("*/1 * * * *", callExternalAuthJob);
