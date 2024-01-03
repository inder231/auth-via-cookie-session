const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const ConnectMongoDBSession = require("connect-mongodb-session");
const MongoDBSession = ConnectMongoDBSession(session);
require("dotenv").config();

const PORT = process.env.PORT;

(() => {
  mongoose
    .connect(process.env.MONGODB_URI)
    .then(() => {
      console.log("connected to db");
    })
    .catch((err) => {
      console.log(`Error connecting to db: ${err}`);
    });
})();

const UserSchema = mongoose.Schema({
  email: { type: String, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model("user", UserSchema);

const app = express();

app.use(express.json());
app.use(
  session({
    name: "nodejs-intern",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new MongoDBSession({
      uri: process.env.MONGODB_URI,
      collection: "sessions",
    }),
    cookie: {
      domain: process.env.COOKIE_DOMAIN,
      maxAge: 1000 * 60, // expired time in milliseconds
      sameSite: "lax",
      secure: false,
      httpOnly: false,
    },
  })
);

app.get("/isLoggedIn", async (req, res) => {
  try {
    req.sessionStore.get(req.sessionID, (err, sessionData) => {
      if (err) {
        throw err;
      } else {
        if (sessionData) {
          res.status(200).json({message:"User is authenticated.",status:true})
        } else {
          // Session doesn't exist in MongoDB
          res.status(400).json({message:"Not authenticated!",status:false})
        }
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ message: error.message,status:false });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const isUserPresent = await User.findOne({ email });
    if (isUserPresent) {
      return res
        .status(400)
        .json({ message: "User already exist!", status: false });
    } else {
      const hashedPassword = bcrypt.hashSync(password, 10);
      const newUser = await User.create({ email, password: hashedPassword });
      return res.status(201).json({
        message: "Registered successfully.",
        user: newUser,
        status: true,
      });
    }
  } catch (error) {
    return res.status(500).json({ message: error.message, status: false });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const isUserPresent = await User.findOne({ email });
    if (!isUserPresent) {
      return res
        .status(400)
        .json({ message: "User does't exist!", status: false });
    } else {
      const isPasswordCorrect = bcrypt.compareSync(
        password,
        isUserPresent.password
      );
      if (isPasswordCorrect) {
        req.session.user = isUserPresent._id;
        return res
          .status(200)
          .json({ message: "LoggedIn successfully.", status: true });
      }
    }
  } catch (error) {
    return res.status(500).json({ message: error.message, status: false });
  }
});

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
