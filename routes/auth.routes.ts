import { Router } from "express";
import {
  getMe,
  logIn,
  register,
} from "../controllers/authentication.controller";
import { protect } from "../middleware/authHandler";

const router = Router();

router.route("/register").post(register);
router.route("/login").post(logIn);

router.route("/me").get(protect, getMe);

export { router };
