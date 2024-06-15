import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { uploadToCloudinary } from "../utils/cloudinaryConfig.js";
import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const verifyEmail = async (req, res) => {
  const { token } = req.params;

  if (!token) {
    return res.status(400).redirect(process.env.FRONTEND_EMAIL_INVALID_URL);
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const email = decoded.email;

    // Find user and update verification status
    const user = await User.findOne({ email, verificationToken: token });
    if (!user) {
      return res.status(400).redirect(process.env.FRONTEND_EMAIL_INVALID_URL);
    }

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    res.status(200).redirect(process.env.FRONTEND_EMAIL_VERIFIED_URL);
  } catch (error) {
    return res.status(400).redirect(process.env.FRONTEND_EMAIL_INVALID_URL);
  }
};
const registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (username === "" || email === "" || password === "") {
      return res.status(400).json({ message: "All fields are required" });
    }

    const isUserExistAlready = await User.findOne({ email });
    if (isUserExistAlready) {
      return res.status(409).json({ message: "User already exist" });
    }

    const encryptedPassword = bcryptjs.hashSync(password, 10);

    const refreshToken = jwt.sign(
      { username, email },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: "30d",
      }
    );

    const avatarFileLocalPath = req.file.path;
    console.log(req.file);

    if (!avatarFileLocalPath) {
      return res
        .status(400)
        .json({ message: "Error occur while uplaoding avatar to server." });
    }

    const avatar = await uploadToCloudinary(avatarFileLocalPath);
    if (!avatar) {
      return res
        .status(400)
        .json({ message: "Error occur.File size is too large." });
    }

    // Generate verification Token
    const verificationToken = jwt.sign(
      { email },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "1h",
      }
    );

    const savedUser = User({
      username,
      email,
      password: encryptedPassword,
      avatar: avatar.url,
      verificationToken,
      refreshToken,
    });
    await savedUser.save();

    // send verification email
    const verificationLink = `http://localhost:3000/api/users/verify-email/${verificationToken}`;
    const mailOptions = {
      from: "khanzaryab249@gmail.com",
      to: email,
      subject: "Email verification",
      text: `Please verify you email by clicking the following link:${verificationLink}`,
    };
    transporter.sendMail(mailOptions, async (err, info) => {
      if (err) {
        console.log(err);
        return res.status(500).json({
          message: err.message,
        });
      } else {
        return res.status(200).json({
          message:
            "User successfully registered. Please check your email to verify your account",
          userData: savedUser,
        });
      }
    });
    savedUser.password = undefined;
    savedUser.refreshToken = undefined;
  } catch (error) {
    return res.status(501).json({ message: error.message });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (email === "" || password === "" || !email || !password) {
      return res.status(400).json({
        message: "All fields are required",
      });
    }

    const isUserRegistered = await User.findOne({ email });
    if (!isUserRegistered) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const isPasswordValid = bcryptjs.compareSync(
      password,
      isUserRegistered.password
    );
    if (!isPasswordValid) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }
    const refreshTokenPayload = {
      username: isUserRegistered.username,
      email: isUserRegistered.email,
    };
    const refreshToken = jwt.sign(
      refreshTokenPayload,
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: "30d",
      }
    );
    const accessTokenPayload = {
      _id: isUserRegistered._id,
      email: isUserRegistered.email,
    };
    const accessToken = jwt.sign(
      accessTokenPayload,
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "1d",
      }
    );

    isUserRegistered.refreshToken = undefined;
    isUserRegistered.password = undefined;
    res
      .status(200)
      .cookie("access_token", accessToken)
      .cookie("refresh_token", refreshToken)
      .json({
        message: "User logged in successfully",
        userData: isUserRegistered,
        tokens: [accessToken, refreshToken],
      });
  } catch (error) {
    return res.status(501).json({ message: error.message });
  }
};

const deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId) {
      return res.status(404).json({
        message: "User id not found",
      });
    }

    const user = await User.findByIdAndDelete(userId);

    res.status(200).json({
      message: "User deleted successfully",
      deletedUser: user,
    });
  } catch (error) {
    res.status(error.statusCode || 501).json({
      message: error.message || "Internal server error",
    });
  }
};

const logoutUser = async (req, res) => {
  try {
    res
      .clearCookie("access_token")
      .clearCookie("refresh_token")
      .status(200)
      .json("User has been signed out");
  } catch (error) {
    return res.status(error.statusCode || 501).json({
      message: error.message || "Internal server error",
    });
  }
};
export { registerUser, loginUser, deleteUser, logoutUser, verifyEmail };
