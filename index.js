import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import nodemailer from "nodemailer";
import UserModel from "./models/Users.js";

const app = express();
app.use(express.json());
app.use(
  cors({
    //for cookies
    origin: ["http://localhost:5173"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(cookieParser());

mongoose.connect('mongodb://127.0.0.1:27017/password_reset_app')
.then(() => {
  console.log('mangobd connected successfully');
})
.catch(err => {
  console.error('Failed to connect to MongoDB', err);
});

//Signup
app.post("/Signup", (req, res) => {
  const { name, email, password } = req.body;
  bcrypt
    .hash(password, 10)
    .then((hash) => {
      const user = new UserModel({ name, email, password: hash });
      user
        .save()
        .then(() => {
          res.status(201).json({ message: "User Created Successfully" });
        })
        .catch((err) => {
          res.status(500).json({ message: err.message });
        });
    })
    .catch((err) => res.json(err));
});

//Login
app.post("/", (req, res) => {
  const { email, password } = req.body;
  UserModel.findOne({ email: email }).then((user) => {
    if (user) {
      bcrypt.compare(password, user.password, (err, response) => {
        if (response) {
          const token = jwt.sign({ email: user.email }, "jwt-secret-token", {
            expiresIn: "1d",
          });
          res.cookie("token", token);
          return res.json({ Status: "success" });
        } else {
          return res.json("password was incorrect");
        }
      });
    } else {
      return res.json("no record Found");
    }
  });
});

const varifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json("token is missing");
  } else {
    jwt.verify(token, "jwt-secret-token", (err, decoded) => {
      if (err) {
        return res.json("token is invalid");
      } else {
        next();
      }
    });
  }
};
app.get("/Home", varifyUser, (req, res) => {
  res.json({ Status: "success" });
});

//Forget Password
app.post("/forget-password", (req, res) => {
  const { email } = req.body;
  UserModel.findOne({ email: email }).then((user) => {
    if (!user) {
      return res.send({ Status: "user not found" });
    }
    const token = jwt.sign({ id: user.id }, "jwt-secret-token", {
      expiresIn: "1d",
    });
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    let mailOptions = {
      to: user.email,
      from: process.env.EMAIL,
      subject: "Password Reset",
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
      Please click on the following link, or paste this into your browser to complete the process:\n\n
      https://localhost:5173/reset-password/${user.id}/${token}
      If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        return res.send({ Status: "success" });
      }
    });
  });
});

//Reset Password
app.post("/reset-password/:id/:token", (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  jwt.verify(token, "jwt-secret-token", (err, decoded) => {
    if (err) {
      return res.json({ Status: "Error with token" });
    } else {
      bcrypt.hash(password, 10).then((hash) => {
        UserModel.findByIdAndUpdate({ _id: id }, { password: hash }).then();
      });
    }
  });
});

app.listen(3000, () => {
  console.log("Server is running Successfully");
});
