// src/controllers/adminExtraController.js

import crypto from "crypto";
import bcrypt from "bcryptjs";
import _ from "lodash";
import Admin from "../models/Admin.js";
import { sendResponse } from "../utils/helpers.js";
import {
	sendVerificationEmail,
	sendResetPasswordEmail,
	sendTwoFactorOTPEmail,
} from "../services/emailService.js";

// Use only the Winston logger
import logger from "../utils/logger.js";

// Helper to generate a random token
const generateToken = () => crypto.randomBytes(20).toString("hex");

// ============
// Verify Email
// ============
// GET /api/v{version}/admin/verify-email?token=XYZ
export const verifyEmail = async (req, res) => {
	try {
		const { token } = req.query;
		if (!token) {
			logger.warn("Verification token missing in request.");
			return sendResponse(res, 400, false, null, "Token is required");
		}

		// Find the admin with a matching, unexpired verification token
		const admin = await Admin.findOne({
			emailVerificationToken: token,
			emailVerificationExpires: { $gt: Date.now() },
		});

		if (!admin) {
			logger.warn(`Invalid or expired token: ${token}`);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Invalid or expired token"
			);
		}

		admin.isVerified = true;
		admin.emailVerificationToken = undefined;
		admin.emailVerificationExpires = undefined;
		await admin.save();

		logger.info(`Email verified for admin: ${admin._id}`);
		return sendResponse(
			res,
			200,
			true,
			null,
			"Email verified successfully"
		);
	} catch (err) {
		logger.error(`Error in verifyEmail: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v{version}/admin/resend-verification
export const resendVerificationEmail = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			logger.warn("Resend verification: Email missing in request.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const admin = await Admin.findOne({ email });
		if (!admin) {
			logger.warn(
				`Resend verification failed: Admin not found (${email})`
			);
			return sendResponse(res, 400, false, null, "Admin not found");
		}
		if (admin.isVerified) {
			logger.info(
				`Admin ${email} already verified; no need to resend email.`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email already verified"
			);
		}

		// Generate new verification token (expires in 24 hours)
		const token = generateToken();
		admin.emailVerificationToken = token;
		admin.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;
		await admin.save();

		await sendVerificationEmail(admin.email, token);

		logger.info(`Resent verification email to admin: ${admin._id}`);
		return sendResponse(res, 200, true, null, "Verification email sent");
	} catch (err) {
		logger.error(`Error in resendVerificationEmail: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ======================
// Forgot Password & Reset
// ======================

// POST /api/v{version}/admin/forgot-password
export const forgotPassword = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			logger.warn("Forgot password: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const admin = await Admin.findOne({ email });
		if (!admin) {
			logger.warn(`Forgot password: Admin not found for email ${email}`);
			return sendResponse(res, 400, false, null, "Admin not found");
		}

		// Generate reset token (expires in 1 hour)
		const token = generateToken();
		admin.forgotPasswordToken = token;
		admin.forgotPasswordExpires = Date.now() + 60 * 60 * 1000;
		await admin.save();

		await sendResetPasswordEmail(admin.email, token);

		logger.info(`Password reset email sent for admin: ${admin._id}`);
		return sendResponse(res, 200, true, null, "Password reset email sent");
	} catch (err) {
		logger.error(`Error in forgotPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v{version}/admin/reset-password
export const resetPassword = async (req, res) => {
	try {
		const allowedFields = ["token", "newPassword", "confirmPassword"];
		const data = _.pick(req.body, allowedFields);

		if (!data.token || !data.newPassword || !data.confirmPassword) {
			logger.warn("Reset password: Missing required fields.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Token and new passwords are required"
			);
		}

		if (data.newPassword !== data.confirmPassword) {
			logger.warn("Reset password: Passwords do not match.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}

		const admin = await Admin.findOne({
			forgotPasswordToken: data.token,
			forgotPasswordExpires: { $gt: Date.now() },
		});
		if (!admin) {
			logger.warn(
				`Reset password failed: Invalid or expired token (${data.token})`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Invalid or expired token"
			);
		}

		const salt = await bcrypt.genSalt(10);
		admin.password = await bcrypt.hash(data.newPassword, salt);
		admin.forgotPasswordToken = undefined;
		admin.forgotPasswordExpires = undefined;
		await admin.save();

		logger.info(`Password reset successful for admin: ${admin._id}`);
		return sendResponse(res, 200, true, null, "Password reset successful");
	} catch (err) {
		logger.error(`Error in resetPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ===========================
// Two-Factor Authentication (OTP)
// ===========================

// POST /api/v{version}/admin/send-otp
export const sendTwoFactorOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			logger.warn("Send OTP: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const admin = await Admin.findOne({ email });
		if (!admin) {
			logger.warn(`Send OTP: Admin not found for email ${email}`);
			return sendResponse(res, 400, false, null, "Admin not found");
		}

		// Generate a 6-digit OTP that expires in 5 minutes
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		admin.twoFactorOTP = otp;
		admin.twoFactorOTPExpires = Date.now() + 5 * 60 * 1000;
		await admin.save();

		await sendTwoFactorOTPEmail(admin.email, otp);

		logger.info(`OTP sent for 2FA to admin: ${admin._id}`);
		return sendResponse(res, 200, true, null, "OTP sent to email");
	} catch (err) {
		logger.error(`Error in sendTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v{version}/admin/verify-otp
export const verifyTwoFactorOTP = async (req, res) => {
	try {
		const { email, otp } = req.body;
		if (!email || !otp) {
			logger.warn("Verify OTP: Email or OTP missing.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email and OTP are required"
			);
		}

		const admin = await Admin.findOne({ email });
		if (
			!admin ||
			!admin.twoFactorOTP ||
			admin.twoFactorOTPExpires < Date.now()
		) {
			logger.warn(
				`Verify OTP failed: OTP invalid or expired for ${email}`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"OTP is invalid or expired"
			);
		}

		if (admin.twoFactorOTP !== otp) {
			logger.warn(
				`Verify OTP failed: Provided OTP does not match for ${email}`
			);
			return sendResponse(res, 400, false, null, "OTP does not match");
		}

		// Clear OTP after successful verification
		admin.twoFactorOTP = undefined;
		admin.twoFactorOTPExpires = undefined;
		await admin.save();

		logger.info(`OTP verified for admin: ${admin._id}`);
		return sendResponse(res, 200, true, null, "OTP verified successfully");
	} catch (err) {
		logger.error(`Error in verifyTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ------------------------------
// Get Verification Status
// ------------------------------
// GET /api/v{version}/admin/verification-status
export const getVerificationStatus = async (req, res) => {
	try {
		// Assumes req.admin is set by an authentication middleware
		const admin = await Admin.findById(req.admin.id);
		if (!admin) {
			logger.warn(
				`Admin not found for verification status: ${req.admin.id}`
			);
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		const status = {
			verified: admin.isVerified,
			message: admin.isVerified
				? "Email is verified"
				: "Email is not verified. Please verify your email.",
		};
		logger.info(`Verification status retrieved for admin: ${admin._id}`);
		return sendResponse(
			res,
			200,
			true,
			status,
			"Verification status retrieved"
		);
	} catch (err) {
		logger.error(`Error in getVerificationStatus: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
