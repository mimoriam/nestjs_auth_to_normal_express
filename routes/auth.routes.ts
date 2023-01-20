import { Router } from "express";
import {
  confirmEmail,
  forgotPass,
  getMe,
  logIn,
  refreshToken,
  register,
  resetPass,
  updatePass,
} from "../controllers/authentication.controller";
import { protect } from "../middleware/authHandler";

const router = Router();

router.route("/register").post(register);
router.route("/login").post(logIn);
router.route("/me").get(protect, getMe);
router.route("/refresh-token").post(protect, refreshToken);
router.route("/confirmemail").get(confirmEmail);
router.route("/forgotpassword").post(forgotPass);
router.route("/updatepassword").patch(protect, updatePass);
router.route("/resetpassword/:resetToken").patch(resetPass);

export { router };
