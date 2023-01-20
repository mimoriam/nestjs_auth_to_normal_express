import { verify } from "jsonwebtoken";
import { ErrorResponse } from "../utils/errorResponse";
import { asyncHandler } from "./asyncHandler";
import { AppDataSource } from "../app";
import { User } from "../models/User.entity";

export const protect = asyncHandler(async (req, res, next) => {
  const userRepo = AppDataSource.getRepository(User);
  let _, token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    [_, token] = req.headers.authorization.split(" ") ?? [];
  }
  // else if (req.cookies.token) {
  //   token = req.cookies.token;
  // }

  if (!token) {
    return next(new ErrorResponse("Not authorized to access this route", 401));
  }

  try {
    // Verify token
    const decoded = verify(token, process.env.JWT_SECRET, {
      audience: process.env.JWT_TOKEN_AUDIENCE,
      issuer: process.env.JWT_TOKEN_ISSUER,
    });

    req.user = await userRepo.findOne({
      where: {
        id: decoded["id"],
      },
    });

    next();
  } catch (err) {
    return next(new ErrorResponse("Not authorized to access this route", 401));
  }
});
