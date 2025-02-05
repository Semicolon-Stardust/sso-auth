// src/controllers/userExtraController.js

import crypto from "crypto";
import bcrypt from "bcryptjs";
import _ from "lodash";
import User from "../models/User.js";
import { sendResponse } from "../utils/helpers.js";
import {
	sendVerificationEmail,
	sendResetPasswordEmail,
	sendTwoFactorOTPEmail,
} from "../services/emailService.js";

// Import loggers
import logger from "../utils/logger.js"; // Winston logger
import pinoLogger from "../utils/pinoLogger.js"; // Pino logger
import bunyanLogger from "../utils/bunyanLogger.js"; // Bunyan logger
import { authLogger } from "../utils/log4jsConfig.js"; // Log4js logger for authentication flows
import signale from "../utils/signaleLogger.js"; // Signale for development logs
import tracerLogger from "../utils/tracerLogger.js"; // Tracer for function call tracing

// Helper to generate a random token
const generateToken = () => crypto.randomBytes(20).toString("hex");

// ============
// Verify Email
// ============
// GET /api/v1/auth/verify-email?token=XYZ
export const verifyEmail = async (req, res) => {
	try {
		const { token } = req.query;
		if (!token) {
			authLogger.warn("Verification token missing in request.");
			return sendResponse(res, 400, false, null, "Token is required");
		}

		// Find the user with a matching, unexpired verification token
		const user = await User.findOne({
			emailVerificationToken: token,
			emailVerificationExpires: { $gt: Date.now() },
		});

		if (!user) {
			authLogger.warn(`Invalid or expired token: ${token}`);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Invalid or expired token"
			);
		}

		user.isVerified = true;
		user.emailVerificationToken = undefined;
		user.emailVerificationExpires = undefined;
		await user.save();

		logger.info(`Email verified for user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: Email verified");
		bunyanLogger.info({ userId: user._id }, "Email verified successfully");
		signale.success(`Email verified successfully for ${user.email}`);
		tracerLogger.trace(`verifyEmail executed for user ${user._id}`);

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

// POST /api/v1/auth/resend-verification
export const resendVerificationEmail = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Resend verification: Email missing in request.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			authLogger.warn(
				`Resend verification failed: User not found (${email})`
			);
			return sendResponse(res, 400, false, null, "User not found");
		}
		if (user.isVerified) {
			authLogger.info(
				`User ${email} already verified; no need to resend email.`
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
		user.emailVerificationToken = token;
		user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;
		await user.save();

		await sendVerificationEmail(user.email, token);

		logger.info(`Resent verification email to user: ${user._id}`);
		signale.success(`Verification email resent to ${user.email}`);
		tracerLogger.trace(
			`resendVerificationEmail executed for user ${user._id}`
		);

		return sendResponse(res, 200, true, null, "Verification email sent");
	} catch (err) {
		logger.error(`Error in resendVerificationEmail: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ======================
// Forgot Password & Reset
// ======================

// POST /api/v1/auth/forgot-password
export const forgotPassword = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Forgot password: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			authLogger.warn(
				`Forgot password: User not found for email ${email}`
			);
			return sendResponse(res, 400, false, null, "User not found");
		}

		// Generate reset token (expires in 1 hour)
		const token = generateToken();
		user.forgotPasswordToken = token;
		user.forgotPasswordExpires = Date.now() + 60 * 60 * 1000;
		await user.save();

		await sendResetPasswordEmail(user.email, token);

		logger.info(`Password reset email sent for user: ${user._id}`);
		signale.success(`Password reset email sent to ${user.email}`);
		tracerLogger.trace(`forgotPassword executed for user ${user._id}`);

		return sendResponse(res, 200, true, null, "Password reset email sent");
	} catch (err) {
		logger.error(`Error in forgotPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/auth/reset-password
export const resetPassword = async (req, res) => {
	try {
		const allowedFields = ["token", "newPassword", "confirmPassword"];
		const data = _.pick(req.body, allowedFields);

		if (!data.token || !data.newPassword || !data.confirmPassword) {
			authLogger.warn("Reset password: Missing required fields.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Token and new passwords are required"
			);
		}

		if (data.newPassword !== data.confirmPassword) {
			authLogger.warn("Reset password: Passwords do not match.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}

		const user = await User.findOne({
			forgotPasswordToken: data.token,
			forgotPasswordExpires: { $gt: Date.now() },
		});
		if (!user) {
			authLogger.warn(
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
		user.password = await bcrypt.hash(data.newPassword, salt);
		user.forgotPasswordToken = undefined;
		user.forgotPasswordExpires = undefined;
		await user.save();

		logger.info(`Password reset successful for user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: Password reset");
		signale.success(`Password reset successful for ${user.email}`);
		tracerLogger.trace(`resetPassword executed for user ${user._id}`);

		return sendResponse(res, 200, true, null, "Password reset successful");
	} catch (err) {
		logger.error(`Error in resetPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ===========================
// Two-Factor Authentication (OTP)
// ===========================

// POST /api/v1/auth/send-otp
export const sendTwoFactorOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Send OTP: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			authLogger.warn(`Send OTP: User not found for email ${email}`);
			return sendResponse(res, 400, false, null, "User not found");
		}

		// Generate a 6-digit OTP that expires in 5 minutes
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		user.twoFactorOTP = otp;
		user.twoFactorOTPExpires = Date.now() + 5 * 60 * 1000;
		await user.save();

		await sendTwoFactorOTPEmail(user.email, otp);

		logger.info(`OTP sent for 2FA to user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: OTP sent for 2FA");
		signale.success(`OTP sent to ${user.email}`);
		tracerLogger.trace(`sendTwoFactorOTP executed for user ${user._id}`);

		return sendResponse(res, 200, true, null, "OTP sent to email");
	} catch (err) {
		logger.error(`Error in sendTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/auth/verify-otp
export const verifyTwoFactorOTP = async (req, res) => {
	try {
		const { email, otp } = req.body;
		if (!email || !otp) {
			authLogger.warn("Verify OTP: Email or OTP missing.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email and OTP are required"
			);
		}

		const user = await User.findOne({ email });
		if (
			!user ||
			!user.twoFactorOTP ||
			user.twoFactorOTPExpires < Date.now()
		) {
			authLogger.warn(
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

		if (user.twoFactorOTP !== otp) {
			authLogger.warn(
				`Verify OTP failed: Provided OTP does not match for ${email}`
			);
			return sendResponse(res, 400, false, null, "OTP does not match");
		}

		// Clear OTP after successful verification
		user.twoFactorOTP = undefined;
		user.twoFactorOTPExpires = undefined;
		await user.save();

		logger.info(`OTP verified for user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: OTP verified for 2FA");
		signale.success(`OTP verified successfully for ${user.email}`);
		tracerLogger.trace(`verifyTwoFactorOTP executed for user ${user._id}`);

		return sendResponse(res, 200, true, null, "OTP verified successfully");
	} catch (err) {
		logger.error(`Error in verifyTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
