const Express = require("express");

const app = new Express();

// set new time every request call

app.use(Express.urlencoded({}));
app.use(Express.json({}));

app.post("/auth", async (req, res) => {
  res.json({
    accessToken: "external_access_token",
  });
});

app.listen(3001, () => {
  console.log("Running on 3001");
});
