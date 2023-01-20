import { asyncHandler } from "../middleware/asyncHandler";
import { AppDataSource } from "../app";
import { User } from "../models/User.entity";
import { ErrorResponse } from "../utils/errorResponse";
import { hash, compare } from "../utils/bcryptService";
import * as jwtService from "jsonwebtoken";
import { createHash, randomBytes, randomUUID } from "crypto";
import {
  insert,
  invalidate,
  InvalidateRefreshTokenError,
  validate,
} from "../utils/refresh-token-ids.storage";
import { createTransport } from "nodemailer";
import { MoreThan } from "typeorm";
import {
  enableTfaForUser,
  generateSecret,
  verifyCode,
} from "./authentication.otp.controller";
import { toFileStream } from "qrcode";

// @desc      Register user
// @route     POST /api/v1/auth/register
// @access    Public
const register = asyncHandler(async (req, res, next) => {
  const userRepo = AppDataSource.getRepository(User);
  const user = new User();

  user.name = req.body.name;
  user.email = req.body.email;
  user.role = req.body.role;
  user.password = await hash(req.body.password);

  // grab token and send to email:
  const confirmEmailToken = await generateEmailConfirmToken(user);

  // Create reset url
  const confirmEmailURL = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/auth/confirmemail?token=${confirmEmailToken}`;

  const message = `You are receiving this email because you need to confirm your email address. Please make a GET request to: \n\n ${confirmEmailURL}`;

  await userRepo.save(user);

  const transporter = createTransport({
    host: "0.0.0.0",
    port: 1025,
  });

  try {
    await transporter.sendMail({
      from: "from@example.com",
      to: user.email,
      subject: "Email Confirm token",
      text: message,
      html: `Click <a href="${confirmEmailURL}">here</a> to reset your password!`,
    });

    return res.status(200).json({
      message: "Confirmation Email Sent!",
    });
  } catch (err) {
    user.confirmEmailToken = null;
    user.isEmailConfirmed = false;

    await userRepo.save(user);

    return next(new ErrorResponse("Email could not be sent", 401));
  }

  return res.status(200).json({
    message: "Registered",
  });
});

const generateEmailConfirmToken = async (user: User) => {
  const confirmationToken = randomBytes(20).toString("hex");

  user.confirmEmailToken = createHash("sha256")
    .update(confirmationToken)
    .digest("hex");

  const confirmTokenExtend = randomBytes(100).toString("hex");
  return `${confirmationToken}.${confirmTokenExtend}`;
};

// @desc      Confirm Email
// @route     GET /api/v1/auth/confirmmail?token={TOKEN}
// @access    Public
const confirmEmail = asyncHandler(async (req, res, next) => {
  const userRepo = AppDataSource.getRepository(User);
  const { token } = req.query;

  if (!token) {
    return next(new ErrorResponse("Invalid", 401));
  }

  const splitToken = token.split(".")[0];

  const confirmEmailToken = createHash("sha256")
    .update(splitToken)
    .digest("hex");

  const user = await userRepo.findOne({
    where: {
      confirmEmailToken: confirmEmailToken,
      isEmailConfirmed: false,
    },
  });

  if (!user) {
    return next(new ErrorResponse("User does not exist", 401));
  }

  user.confirmEmailToken = null;
  user.isEmailConfirmed = true;

  await userRepo.save(user);

  return res.status(200).json({
    message: "Email confirmed",
  });
});

// @desc      Login user
// @route     POST /api/v1/auth/login
// @access    Public
const logIn = asyncHandler(async (req, res, next) => {
  const userRepo = AppDataSource.getRepository(User);

  const user = await userRepo.findOneBy({
    email: req.body.email,
  });

  if (!user) {
    return next(new ErrorResponse("User does not exist", 401));
  }

  const isEqual = await compare(req.body.password, user.password);

  if (!isEqual) {
    return next(new ErrorResponse("Invalid credentials", 401));
  }

  if (user.isTfaEnabled) {
    const isValid = await verifyCode(req.body.tfaCode, user.tfaSecret);

    if (!isValid) {
      return next(new ErrorResponse("Invalid 2FA Code", 401));
    }
  }

  const { accessToken, refreshToken } = await generateTokens(user);

  return res.status(200).json({
    accessToken,
    refreshToken,
  });
});

// @desc      Refresh Tokens using Access Token
// @route     POST /api/v1/auth/refresh-token
// @access    Private
const refreshToken = async (req, res, next) => {
  try {
    const userRepo = AppDataSource.getRepository(User);
    const decoded = jwtService.verify(
      req.body.refreshToken,
      process.env.JWT_SECRET,
      {
        audience: process.env.JWT_TOKEN_AUDIENCE,
        issuer: process.env.JWT_TOKEN_ISSUER,
      }
    );

    const user = await userRepo.findOneByOrFail({
      id: decoded["id"],
    });

    const isValid = await validate(
      parseInt(user.id),
      decoded["refreshTokenId"]
    );

    if (isValid) {
      await invalidate(parseInt(user.id));
    } else {
      return next(new ErrorResponse("Refresh token is invalid", 401));
    }

    const { accessToken, refreshToken } = await generateTokens(user);

    return res.status(200).json({
      accessToken,
      refreshToken,
    });
  } catch (err) {
    if (err instanceof InvalidateRefreshTokenError) {
      // Take action: Notify user that his refresh token may have been stolen
      return next(new ErrorResponse("Access denied", 401));
    }

    return next(new ErrorResponse("Unauthorized", 401));
  }
};

// @desc      Get current logged-in user
// @route     GET /api/v1/auth/me
// @access    Private
const getMe = asyncHandler(async (req, res, next) => {
  // user is already available in req due to the protect middleware
  const user = req["user"];

  res.status(200).json({
    success: true,
    data: user,
  });
});

// @desc      Forgot Password
// @route     POST /api/v1/auth/me
// @access    Public
const forgotPass = asyncHandler(async (req, res, next) => {
  const userRepo = AppDataSource.getRepository(User);

  const user = await userRepo.findOneBy({
    email: req.body.email,
  });

  const resetToken = randomBytes(20).toString("hex");
  user.resetPasswordToken = createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // This one is for the un-hashed token version:
  // const resetToken = Math.random().toString(20).substring(2, 12);
  // user.resetPasswordToken = resetToken;

  user.resetPasswordExpire = new Date(Date.now() + 10 * 60 * 1000);

  await userRepo.save(user);

  const transporter = createTransport({
    host: "0.0.0.0",
    port: 1025,
  });

  const resetUrl = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/auth/resetpassword/${resetToken}`;

  const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetUrl}`;

  try {
    await transporter.sendMail({
      from: "from@example.com",
      to: req.body.email,
      subject: "Password reset token",
      text: message,
      html: `Click <a href="${resetUrl}">here</a> to reset your password!`,
    });

    return res.status(200).json({
      message: "Email Sent with Password Reset URL!",
    });
  } catch (err) {
    user.resetPasswordToken = null;
    user.resetPasswordExpire = null;

    await userRepo.save(user);

    return next(new ErrorResponse("Email could not be sent", 401));
  }
});

// @desc      Update Password
// @route     PATCH /api/v1/auth/updatepassword
// @access    PRIVATE
const updatePass = asyncHandler(async (req, res, next) => {
  const userRepo = AppDataSource.getRepository(User);
  const user = req["user"];

  const isEqual = await compare(req.body.currentPassword, user.password);

  if (!isEqual) {
    return next(new ErrorResponse("Invalid credentials", 401));
  }

  user.password = await hash(req.body.newPassword);

  await userRepo.save(user);

  return res.status(200).json({
    message: "Password updated",
  });
});

// @desc      Reset Password
// @route     PATCH /api/v1/auth/resetpassword/{TOKEN}
// @access    Public
const resetPass = asyncHandler(async (req, res, next) => {
  const userRepo = AppDataSource.getRepository(User);
  const resetPasswordToken = createHash("sha256")
    .update(req.params.resetToken)
    .digest("hex");

  const user = await userRepo.findOne({
    where: {
      // resetPasswordToken: resetToken,
      resetPasswordToken: resetPasswordToken,
      resetPasswordExpire: MoreThan(new Date(Date.now())),
    },
  });

  if (!user) {
    return next(new ErrorResponse("User does not exist", 401));
  }

  user.password = await hash(req.body.password);
  user.resetPasswordToken = null;
  user.resetPasswordExpire = null;

  await userRepo.save(user);

  return res.status(200).json({
    message: "Password resetted!",
  });
});

const generateQrCode = asyncHandler(async (req, res, next) => {
  const user = req["user"];
  const { secret, uri } = await generateSecret(user.email);

  await enableTfaForUser(user.email, secret);

  res.type("png");
  return toFileStream(res, uri);
});

const generateTokens = async (user: User) => {
  const refreshTokenId = randomUUID();

  const [accessToken, refreshToken] = await Promise.all([
    jwtService.sign(
      {
        id: user.id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {
        audience: process.env.JWT_TOKEN_AUDIENCE,
        issuer: process.env.JWT_TOKEN_ISSUER,
        expiresIn: parseInt(process.env.JWT_ACCESS_TOKEN_TTL ?? "3600", 10),
      }
    ),
    // Added refreshTokenId in the JWT:
    jwtService.sign(
      {
        id: user.id,
        refreshTokenId: refreshTokenId,
      },
      process.env.JWT_SECRET,
      {
        audience: process.env.JWT_TOKEN_AUDIENCE,
        issuer: process.env.JWT_TOKEN_ISSUER,
        expiresIn: parseInt(process.env.JWT_REFRESH_TOKEN_TTL ?? "3600", 10),
      }
    ),
  ]);

  await insert(parseInt(user.id), refreshTokenId);

  return {
    accessToken,
    refreshToken,
  };
};

export {
  register,
  logIn,
  getMe,
  refreshToken,
  confirmEmail,
  forgotPass,
  resetPass,
  updatePass,
  generateQrCode,
};
