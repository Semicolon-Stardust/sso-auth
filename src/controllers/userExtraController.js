import crypto from "crypto";
import bcrypt from "bcryptjs";
import User from "../models/User.js";
import {
	sendVerificationEmail,
	sendResetPasswordEmail,
	sendTwoFactorOTPEmail,
} from "../services/emailService.js";
import { sendResponse } from "../utils/helpers.js";

// Helper to generate a random token (for verification and password reset)
const generateToken = () => crypto.randomBytes(20).toString("hex");

// =======================
// VERIFY EMAIL ADDRESS
// =======================

// Endpoint: GET /api/v1/auth/verify-email?token=...
export const verifyEmail = async (req, res) => {
	try {
		const { token } = req.query;
		if (!token) {
			return sendResponse(res, 400, false, null, "Token is required");
		}
		// Find user with a matching verification token that has not expired
		const user = await User.findOne({
			emailVerificationToken: token,
			emailVerificationExpires: { $gt: Date.now() },
		});
		if (!user) {
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
		return sendResponse(
			res,
			200,
			true,
			null,
			"Email verified successfully"
		);
	} catch (error) {
		console.error(error);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Endpoint: POST /api/v1/auth/resend-verification
export const resendVerificationEmail = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const user = await User.findOne({ email });
		if (!user) {
			return sendResponse(res, 400, false, null, "User not found");
		}
		if (user.isVerified) {
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email already verified"
			);
		}
		// Generate a new token (expires in 24 hours)
		const token = generateToken();
		user.emailVerificationToken = token;
		user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
		await user.save();
		await sendVerificationEmail(user.email, token);
		return sendResponse(res, 200, true, null, "Verification email sent");
	} catch (error) {
		console.error(error);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// =======================
// FORGOT PASSWORD & RESET PASSWORD
// =======================

// Endpoint: POST /api/v1/auth/forgot-password
export const forgotPassword = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const user = await User.findOne({ email });
		if (!user) {
			return sendResponse(res, 400, false, null, "User not found");
		}
		// Generate a reset token (expires in 1 hour)
		const token = generateToken();
		user.forgotPasswordToken = token;
		user.forgotPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour
		await user.save();
		await sendResetPasswordEmail(user.email, token);
		return sendResponse(res, 200, true, null, "Password reset email sent");
	} catch (error) {
		console.error(error);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Endpoint: POST /api/v1/auth/reset-password
export const resetPassword = async (req, res) => {
	try {
		const { token, newPassword, confirmPassword } = req.body;
		if (!token || !newPassword || !confirmPassword) {
			return sendResponse(
				res,
				400,
				false,
				null,
				"Token and new passwords are required"
			);
		}
		if (newPassword !== confirmPassword) {
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}
		// Find user with a valid reset token
		const user = await User.findOne({
			forgotPasswordToken: token,
			forgotPasswordExpires: { $gt: Date.now() },
		});
		if (!user) {
			return sendResponse(
				res,
				400,
				false,
				null,
				"Invalid or expired token"
			);
		}
		// Hash the new password and update user record
		const salt = await bcrypt.genSalt(10);
		user.password = await bcrypt.hash(newPassword, salt);
		user.forgotPasswordToken = undefined;
		user.forgotPasswordExpires = undefined;
		await user.save();
		return sendResponse(res, 200, true, null, "Password reset successful");
	} catch (error) {
		console.error(error);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// =======================
// TWO-FACTOR AUTHENTICATION (OTP)
// =======================

// Endpoint: POST /api/v1/auth/send-otp
export const sendTwoFactorOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const user = await User.findOne({ email });
		if (!user) {
			return sendResponse(res, 400, false, null, "User not found");
		}
		// Generate a 6-digit OTP and set it to expire in 5 minutes
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		user.twoFactorOTP = otp;
		user.twoFactorOTPExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
		await user.save();
		await sendTwoFactorOTPEmail(user.email, otp);
		return sendResponse(res, 200, true, null, "OTP sent to email");
	} catch (error) {
		console.error(error);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Endpoint: POST /api/v1/auth/verify-otp
export const verifyTwoFactorOTP = async (req, res) => {
	try {
		const { email, otp } = req.body;
		if (!email || !otp) {
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
			return sendResponse(
				res,
				400,
				false,
				null,
				"OTP is invalid or expired"
			);
		}
		if (user.twoFactorOTP !== otp) {
			return sendResponse(res, 400, false, null, "OTP does not match");
		}
		// Clear OTP after successful verification
		user.twoFactorOTP = undefined;
		user.twoFactorOTPExpires = undefined;
		await user.save();
		return sendResponse(res, 200, true, null, "OTP verified successfully");
	} catch (error) {
		console.error(error);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
