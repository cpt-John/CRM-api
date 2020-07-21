const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const cryptoRandomString = require("crypto-random-string");
const mongodb = require("mongodb");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

const port = process.env.PORT || 3000;
dotenv.config();

const key = process.env.KEY;
const saltRounds = 6;
const tokenExpiery = { login: 60 * 24, passwordReset: 10 };

app.use(bodyParser.json());
app.use(cors());

app.listen(port, () => {
  console.log("app listing in port " + port);
});

//mailing
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.C_EMAIL,
    pass: process.env.C_PASSWORD,
  },
});

async function Mail(toMail, link, data) {
  let mailOptions = {
    from: process.env.EMAIL,
    to: toMail,
    subject: "verification link",

    html: `<p>${data}</p></br>
    <a href=${link}>Click HERE</a>`,
  };
  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log("error is " + error);
        reject(error);
      } else {
        console.log("Email sent: " + info.response);
        resolve("mailed");
      }
    });
  });
}

//mongodb
const dbName = "CRM";
const collName1 = "users";
const collName2 = "leads";
const collName3 = "requests";
//mongodb://localhost:27017/?readPreference=primary&appname=MongoDB%20Compass%20Community&ssl=false
const uri = `mongodb+srv://${process.env.D_EMAIL}:${process.env.D_PASSWORD}@cluster0-lyx1k.mongodb.net/CRM?retryWrites=true&w=majority`;
// const uri = `mongodb://localhost:27017/?readPreference=primary&ssl=false`;
const mongoClient = mongodb.MongoClient;

app.post("/login", async function (req, res) {
  if (!req.body["email"] || !req.body["password"]) {
    res.status(400).json({
      message: "email or password missing",
    });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  let result;
  try {
    result = await collection.findOne({ email: req.body["email"] });
    if (!result) {
      res.status(400).json({ message: "email is not registered" });
      return;
    } else if (result["verified"] !== true) {
      res.status(400).json({ message: "email is not verified" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
  } finally {
    client.close();
  }
  try {
    let pass = await bcrypt.compare(req.body["password"], result["password"]);
    if (!pass) {
      res.status(401).json({ message: "wrong password" });
    } else if (pass) {
      let token_expiry = tokenExpiery["login"];
      let token = jwt.sign({ email: req.body["email"], type: "login" }, key, {
        expiresIn: token_expiry + "m",
      });
      res.status(200).json({ message: "credentials verified!", token });
    }
  } catch {
    res.status(500).json({ message: "couldn't verify password" });
  }
});

app.post("/register", async function (req, res) {
  if (!req.body["email"] || !req.body["password"] || !req.body["name"]) {
    res.status(400).json({
      message: "email or password or name missing",
    });
    return;
  }
  try {
    let hash = await bcrypt.hash(req.body["password"], saltRounds);
    req.body["password"] = hash;
  } catch {
    res.status(400).json({
      message: "hashing failed",
    });
    return;
  }

  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  try {
    let result = await collection.findOne({ email: req.body["email"] });
    if (result) {
      res.status(400).json({ message: "email already exists" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }
  try {
    let new_obj = {
      email: req.body.email,
      name: req.body.name,
      password: req.body.password,
      verified: false,
      role: 4,
    };
    await collection.insertOne(new_obj);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "filed to register" });
    return;
  } finally {
    client.close();
  }
  let token = jwt.sign(
    { email: req.body["email"], type: "mailVerification" },
    key
  );
  let link = token;
  let text = `use token to verify: ${token}`;
  let result = await Mail(req.body["email"], link, text).catch((err) => {
    res.status(500).json({ message: "filed to send mail" });
  });
  if (result) {
    res
      .status(200)
      .json({ message: "verification mail send to " + req.body["email"] });
  }
});

app.post("/verifyEmail", async function (req, res) {
  if (!req.body["jwt"]) {
    res.status(400).json({
      message: "token missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "invalid token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "mailVerification") {
    try {
      let result = await collection.updateOne(
        { email: data["email"] },
        { $set: { verified: true } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        res
          .status(200)
          .json({ message: "your email has been verified you can login now" });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
  }
});

app.post("/resetPassLink", async function (req, res) {
  if (!req.body["email"]) {
    res.status(400).json({
      message: "email  missing",
    });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  try {
    let result = await collection.findOne({ email: req.body["email"] });
    if (!result) {
      res.status(400).json({ message: "email is not registered" });
      return;
    } else if (result["verified"] !== true) {
      res.status(400).json({ message: "email is not verified" });
      return;
    }
  } catch (err) {
    res.status(500).json({ message: "filed to retreive" });
    client.close();
    return;
  }

  let token_expiry = tokenExpiery["passwordReset"];
  let token = jwt.sign(
    { email: req.body["email"], type: "passwordReset" },
    key,
    { expiresIn: token_expiry + "m" }
  );
  let link = token;
  let text = `reset password token is valid only for ${token_expiry} minute(s)
                token is : ${token}`;
  let result = await Mail(req.body["email"], link, text).catch((err) => {
    res.status(500).json({ message: "filed to send mail" });
  });
  if (result) {
    res
      .status(200)
      .json({ message: "reset link send to " + req.body["email"] });
  }
});

app.post("/resetPass", async function (req, res) {
  if (!req.body["jwt"] || !req.body["new_password"]) {
    res.status(400).json({
      message: "token or password missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "invalid token" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "passwordReset") {
    //new pass
    let hash;
    try {
      hash = await bcrypt.hash(req.body["new_password"], saltRounds);
    } catch {
      res.status(400).json({
        message: "hashing failed",
      });
      return;
    }
    //set new pass
    try {
      let result = await collection.updateOne(
        { email: data["email"] },
        { $set: { password: hash } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        res.status(200).json({
          message: "your password has been reset",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
    client.close();
  }
});

// Session middle ware
const verifySession = async (req, res, next) => {
  if (!req.body["jwt"]) {
    res.status(400).json({
      message: "token missing",
    });
    return;
  }
  let token = req.body["jwt"];
  let data;
  try {
    data = jwt.verify(token, key);
  } catch (err) {
    res.status(401).json({ message: "session ended login again" });
    return;
  }
  const client = await mongoClient
    .connect(uri, {
      useUnifiedTopology: true,
    })
    .catch((err) => {
      res.status(500).json({ message: "filed to connect db" });
    });
  if (!client) {
    return;
  }
  const collection = client.db(dbName).collection(collName1);
  if (data["type"] == "login") {
    try {
      let result = await collection.findOne({ email: data["email"] });
      if (!result) {
        res.status(500).json({ message: "email couldn't be verified" });
        return;
      } else {
        next({ name: result.name, role: result.role });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to retreive" });
      return;
    } finally {
      client.close();
    }
  } else {
    res.status(401).json({ message: "token error" });
    client.close();
  }
};

// user access middle ware
const verifyAccess = (Role) => async (user, req, res, next) => {
  if (user.role <= Role) {
    next(user);
  } else res.status(400).json({ message: "you dont have permission" });
};

app.post(
  "/addLead",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.body["lead_name"] || !req.body["details"] || !req.body["status"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "new",
      "contacted",
      "quantified",
      "lost",
      "cancelled",
      "confirmed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName2);
    try {
      let new_obj = {
        lead_name: req.body.lead_name,
        added_by: user.name,
        status: req.body.status,
        details: req.body.details,
      };
      await collection.insertOne(new_obj);
      res.status(200).json({ message: "added" });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "failed to add" });
      return;
    } finally {
      client.close();
    }
  }
);

app.post(
  "/getLead/:id?",
  verifySession,
  verifyAccess(4),
  async (user, req, res, next) => {
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName2);
    try {
      if (!id) {
        let results = await collection.find({}).toArray();
        res.status(200).json({ results });
      } else {
        let result = await collection.findOne({
          _id: mongodb.ObjectID(id),
        });
        res.status(200).json({ result });
      }
    } catch (err) {
      res.status(500).json({ message: "filed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.post(
  "/updateLead",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.body["lead_id"] || !req.body["status"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "new",
      "contacted",
      "quantified",
      "lost",
      "cancelled",
      "confirmed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName2);
    try {
      let result = await collection.updateOne(
        { _id: mongodb.ObjectID(req.body.lead_id) },
        { $set: { status: req.body.status } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "lead_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "status updated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "filed to update" });
      return;
    } finally {
      client.close();
    }
  }
);

app.post(
  "/addServiceTicket",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (
      !req.body["ticket_name"] ||
      !req.body["details"] ||
      !req.body["status"]
    ) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "created",
      "open",
      "in-process",
      "released",
      "cancelled",
      "completed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "filed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName3);
    try {
      let new_obj = {
        ticket_name: req.body.ticket_name,
        added_by: user.name,
        status: req.body.status,
        details: req.body.details,
      };
      await collection.insertOne(new_obj);
      res.status(200).json({ message: "added" });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "failed to add" });
      return;
    } finally {
      client.close();
    }
  }
);

app.post(
  "/getServiceTickets/:id?",
  verifySession,
  verifyAccess(4),
  async (user, req, res, next) => {
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName3);
    try {
      if (!id) {
        let results = await collection.find({}).toArray();
        res.status(200).json({ results });
      } else {
        let result = await collection.findOne({
          _id: mongodb.ObjectID(id),
        });
        res.status(200).json({ result });
      }
    } catch (err) {
      res.status(500).json({ message: "failed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.post(
  "/updateServiceTicket",
  verifySession,
  verifyAccess(3),
  async (user, req, res, next) => {
    if (!req.body["ticket_id"] || !req.body["status"]) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let status_choise = [
      "created",
      "open",
      "in-process",
      "released",
      "cancelled",
      "completed",
    ];
    if (!status_choise.includes(req.body["status"])) {
      res.status(400).json({
        message: "bad request (wrong status code)",
      });
      return;
    }
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    const collection = client.db(dbName).collection(collName3);
    try {
      let result = await collection.updateOne(
        { _id: mongodb.ObjectID(req.body.lead_id) },
        { $set: { status: req.body.status } }
      );
      if (!result.matchedCount) {
        res.status(500).json({ message: "ticket_id doesnt exist" });
        return;
      } else {
        res.status(200).json({
          message: "status updated",
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "failed to update" });
      return;
    } finally {
      client.close();
    }
  }
);

app.post(
  "/getUsers/:id?",
  verifySession,
  verifyAccess(2),
  async (user, req, res, next) => {
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName1);
    try {
      let query = user.role == 2 ? { role: { $gt: 2 } } : {};
      if (!id) {
        let results = await collection.find(query).toArray();
        res.status(200).json({ results });
      } else {
        query["_id"] = mongodb.ObjectID(id);
        let result = await collection.findOne(query);
        res.status(200).json({ result });
      }
    } catch (err) {
      res.status(500).json({ message: "failed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);

app.post(
  "/updateUserRole/:id",
  verifySession,
  verifyAccess(2),
  async (user, req, res, next) => {
    let roles = [2, 3, 4];
    if (
      !req.body["role"] ||
      !roles.includes(parseInt(req.body.role)) ||
      user.role >= parseInt(req.body.role)
    ) {
      res.status(400).json({
        message: "bad request",
      });
      return;
    }
    let role = parseInt(req.body.role);
    const client = await mongoClient
      .connect(uri, {
        useUnifiedTopology: true,
      })
      .catch((err) => {
        res.status(500).json({ message: "failed to connect db" });
      });
    if (!client) {
      return;
    }
    let id = null;
    if (req.params.hasOwnProperty("id")) id = req.params["id"];
    const collection = client.db(dbName).collection(collName1);
    try {
      let query = user.role == 2 ? { role: { $gt: 2 } } : {};
      query["_id"] = mongodb.ObjectID(id);
      let result = await collection.updateOne(query, { $set: { role: role } });
      if (!result.matchedCount) {
        res.status(500).json({ message: "user not found" });
        return;
      } else {
        res.status(200).json({
          message: "role updated",
        });
      }
    } catch (err) {
      res.status(500).json({ message: "failed to retreive" });
    } finally {
      client.close();
      return;
    }
  }
);
