// src/routes/userExtraRoutes.js
import { Router } from "express";
import {
	verifyEmail,
	resendVerificationEmail,
	forgotPassword,
	resetPassword,
	sendTwoFactorOTP,
	verifyTwoFactorOTP,
	getVerificationStatus,
} from "../controllers/userExtraController.js";

export default function userExtraRoutes(version) {
	const router = Router();

	// Email verification endpoints
	router.get(`/api/v${version}/user/verify-email`, verifyEmail);
	router.post(
		`/api/v${version}/user/resend-verification`,
		resendVerificationEmail
	);

	// Verification status endpoint
	router.get(
		`/api/v${version}/user/verification-status`,
		getVerificationStatus
	);

	// Password reset endpoints
	router.post(`/api/v${version}/user/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/user/reset-password`, resetPassword);

	// Two-factor authentication endpoints
	router.post(`/api/v${version}/user/send-otp`, sendTwoFactorOTP);
	router.post(`/api/v${version}/user/verify-otp`, verifyTwoFactorOTP);

	return router;
}
