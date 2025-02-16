import { Router } from "express";
import {
	verifyEmail,
	resendVerificationEmail,
	forgotPassword,
	resetPassword,
	sendTwoFactorOTP,
	verifyTwoFactorOTP,
	getVerificationStatus,
	enableTwoFactorAuth,
	disableTwoFactorAuth,
} from "../controllers/adminExtraController.js";
import { adminProtect } from "../middlewares/authMiddleware.js"; // Ensure you import your adminProtect

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
		adminProtect,
		getVerificationStatus
	);

	// Password reset endpoints
	router.post(`/api/v${version}/admin/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/admin/reset-password`, resetPassword);

	// Two-factor authentication endpoints
	router.post(`/api/v${version}/admin/send-otp`, sendTwoFactorOTP);
	router.post(`/api/v${version}/admin/verify-otp`, verifyTwoFactorOTP);

	// New endpoints for enabling/disabling two-factor auth
	router.post(
		`/api/v${version}/admin/enable-two-factor`,
		adminProtect,
		enableTwoFactorAuth
	);
	router.post(
		`/api/v${version}/admin/disable-two-factor`,
		adminProtect,
		disableTwoFactorAuth
	);

	return router;
}
