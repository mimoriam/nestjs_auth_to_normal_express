import { asyncHandler } from "../middleware/asyncHandler";
import { AppDataSource } from "../app";
import { User } from "../models/User.entity";
import { ErrorResponse } from "../utils/errorResponse";
import { hash, compare } from "../utils/bcryptService";
import * as jwtService from "jsonwebtoken";
import { randomUUID } from "crypto";
import {
  insert,
  invalidate,
  InvalidateRefreshTokenError,
  validate,
} from "../utils/refresh-token-ids.storage";

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

  await userRepo.save(user);

  return res.status(200).json({
    message: "Registered",
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

  const { accessToken, refreshToken } = await generateTokens(user);

  return res.status(200).json({
    accessToken,
    refreshToken,
  });
});

// @desc      Refresh Tokens using Access Token
// @route     GET /api/v1/auth/refresh-token
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

export { register, logIn, getMe, refreshToken };
