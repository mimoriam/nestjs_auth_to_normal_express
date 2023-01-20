import { asyncHandler } from "../middleware/asyncHandler";
import { AppDataSource } from "../app";
import { User } from "../models/User.entity";
import { ErrorResponse } from "../utils/errorResponse";
import { hash, compare } from "../utils/bcryptService";
import * as jwtService from "jsonwebtoken";

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

  const { accessToken } = await generateTokens(user);

  return res.status(200).json({
    accessToken,
  });
});

const generateTokens = async (user: User) => {
  const accessToken = jwtService.sign(
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
  );

  return {
    accessToken,
  };
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

export { register, logIn, getMe };
