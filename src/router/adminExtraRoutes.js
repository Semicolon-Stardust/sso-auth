// src/routes/adminExtraRoutes.js

import { Router } from "express";
import {
	verifyEmail,
	resendVerificationEmail,
	forgotPassword,
	resetPassword,
	sendTwoFactorOTP,
	verifyTwoFactorOTP,
	getVerificationStatus,
} from "../controllers/adminExtraController.js";

export default function adminExtraRoutes(version) {
	const router = Router();

	// Email verification endpoints
	router.get(`/api/v${version}/admin/verify-email`, verifyEmail);
	router.post(
		`/api/v${version}/admin/resend-verification`,
		resendVerificationEmail
	);

	// Verification status endpoint
	router.get(
		`/api/v${version}/admin/verification-status`,
		getVerificationStatus
	);

	// Password reset endpoints
	router.post(`/api/v${version}/admin/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/admin/reset-password`, resetPassword);

	// Two-factor authentication endpoints
	router.post(`/api/v${version}/admin/send-otp`, sendTwoFactorOTP);
	router.post(`/api/v${version}/admin/verify-otp`, verifyTwoFactorOTP);

	return router;
}
