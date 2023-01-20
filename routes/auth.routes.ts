import { Router } from "express";
import {
  confirmEmail,
  forgotPass,
  generateQrCode,
  getMe,
  logIn,
  refreshToken,
  register,
  resetPass,
  updatePass,
} from "../controllers/authentication.controller";
import { protect } from "../middleware/authHandler";
import { authorize } from "../middleware/permissionHandler";

const router = Router();

router.route("/register").post(register);
router.route("/login").post(logIn);
router.route("/me").get(protect, getMe);
router.route("/refresh-token").post(protect, refreshToken);
router.route("/confirmemail").get(confirmEmail);
router.route("/forgotpassword").post(forgotPass);
router.route("/updatepassword").patch(protect, authorize("admin"), updatePass);
router.route("/resetpassword/:resetToken").patch(resetPass);
router.route("/2fa/generate").post(protect, generateQrCode);

export { router };
