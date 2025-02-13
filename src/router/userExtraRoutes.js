import { Router } from "express";
import {
	verifyEmail,
	resendVerificationEmail,
	forgotPassword,
	resetPassword,
	sendTwoFactorOTP,
	verifyTwoFactorOTP,
} from "../controllers/userExtraController.js";

export default function userExtraRoutes(version) {
	const router = Router();

	// Email verification endpoints
	router.get(`/api/v${version}/auth/verify-email`, verifyEmail);
	router.post(
		`/api/v${version}/auth/resend-verification`,
		resendVerificationEmail
	);

	// Password reset endpoints
	router.post(`/api/v${version}/auth/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/auth/reset-password`, resetPassword);

	// Two-factor authentication endpoints
	router.post(`/api/v${version}/auth/send-otp`, sendTwoFactorOTP);
	router.post(`/api/v${version}/auth/verify-otp`, verifyTwoFactorOTP);

	return router;
}
