// src/controllers/adminController.js

import bcrypt from "bcryptjs";
import _ from "lodash";
import { z } from "zod";
import crypto from "crypto"; // NEW: to generate verification token
import Admin from "../models/Admin.js";
import Session from "../models/Session.js";
import {
	generateAdminToken,
	verifyAdminToken,
} from "../services/tokenServices.js";
import { sendResponse, formatError } from "../utils/helpers.js";
import {
	sendAdminVerificationEmail,
	sendAdminTwoFactorOTPEmail,
} from "../services/emailService.js"; // NEW: to send email

// Use only one logger (Winston)
import logger from "../utils/logger.js";

// ------------------------------
// Zod Schemas for Admin Actions
// ------------------------------

const adminRegisterSchema = z.object({
	name: z.string().min(1, { message: "Name is required" }),
	email: z
		.string()
		.email({ message: "Invalid email format" })
		.refine((val) => val.endsWith("@dayadevraha.com"), {
			message: "Admin email must be a @dayadevraha.com email",
		}),
	password: z
		.string()
		.min(6, { message: "Password must be at least 6 characters long" }),
	confirmPassword: z.string().min(6, {
		message: "Confirm password must be at least 6 characters long",
	}),
	adminKey: z.string().min(1, { message: "Admin key is required" }),
	role: z.enum(["Admin", "Super Admin", "Moderator"]),
	permissions: z.array(z.string()).optional(),
	accessLevel: z.number().min(1).max(5).optional(),
	dateOfBirth: z.string().optional(),
	emergencyRecoveryContact: z.string().optional(),
	// Optional boolean flags
	canManageUsers: z.boolean().optional(),
	canManageContent: z.boolean().optional(),
	canManagePayments: z.boolean().optional(),
	canViewReports: z.boolean().optional(),
	canApproveNewAdmins: z.boolean().optional(),
	canSuspendUsers: z.boolean().optional(),
	canDeleteData: z.boolean().optional(),
	canExportData: z.boolean().optional(),
	superAdminKey: z.string().optional(),
	canPromoteDemoteAdmins: z.boolean().optional(),
	canModifyAdminPermissions: z.boolean().optional(),
	canOverrideSecuritySettings: z.boolean().optional(),
});

// Helper to extract session data
const getSessionData = (req, token) => ({
	ipAddress:
		req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown",
	location: "Unknown",
	userAgent: req.headers["user-agent"] || "Unknown",
	token,
});

// ------------------------------
// Admin Controller Functions
// ------------------------------

// Register a new admin
export const registerAdmin = async (req, res) => {
	try {
		const data = _.pick(req.body, [
			"name",
			"email",
			"password",
			"confirmPassword",
			"adminKey",
			"role",
			"permissions",
			"accessLevel",
			"dateOfBirth",
			"emergencyRecoveryContact",
		]);
		const parsedData = adminRegisterSchema.parse(data);

		// Check if passwords match
		if (parsedData.password !== parsedData.confirmPassword) {
			logger.warn("Admin registration failed: Passwords do not match.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}
		delete parsedData.confirmPassword;

		// Validate admin key
		if (
			parsedData.role !== "Super Admin" &&
			parsedData.adminKey !== process.env.ADMIN_KEY
		) {
			logger.warn(`Invalid admin key for ${parsedData.email}`);
			return sendResponse(res, 401, false, null, "Invalid admin key");
		}
		if (
			parsedData.role === "Super Admin" &&
			parsedData.superAdminKey !== process.env.SUPER_ADMIN_KEY
		) {
			logger.warn(`Invalid super admin key for ${parsedData.email}`);
			return sendResponse(
				res,
				401,
				false,
				null,
				"Invalid super admin key"
			);
		}

		// Check if admin exists
		let admin = await Admin.findOne({ email: parsedData.email });
		if (admin) {
			logger.warn(`Admin with email ${parsedData.email} already exists.`);
			return sendResponse(res, 400, false, null, "Admin already exists");
		}

		// Hash the password
		const salt = await bcrypt.genSalt(10);
		parsedData.password = await bcrypt.hash(parsedData.password, salt);

		// Create admin (email remains unverified by default)
		admin = await Admin.create(parsedData);

		// --- NEW: Generate verification token, update admin, and send verification email ---
		const verificationToken = crypto.randomBytes(20).toString("hex");
		admin.emailVerificationToken = verificationToken;
		admin.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours expiry
		await admin.save();
		await sendAdminVerificationEmail(admin.email, verificationToken);
		// -----------------------------------------------------------------------------

		// Generate JWT token for login
		const token = generateAdminToken({
			id: admin._id,
			email: admin.email,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};
		res.cookie("admin-token", token, cookieOptions);

		// Create a session record
		await Session.create({
			user: admin._id,
			userModel: "Admin",
			...getSessionData(req, token),
		});

		logger.info(`Admin registered: ${admin._id}`);

		return sendResponse(
			res,
			201,
			true,
			_.pick(admin, [
				"_id",
				"name",
				"email",
				"role",
				"accessLevel",
				"permissions",
			]),
			"Admin registered successfully. Please verify your email."
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			logger.error("Validation error during admin registration.");
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		logger.error(`Error in registerAdmin: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Login admin
export const loginAdmin = async (req, res) => {
	try {
		const credentials = _.pick(req.body, ["email", "password"]);
		const parsedCreds = z
			.object({
				email: z.string().email({ message: "Invalid email format" }),
				password: z
					.string()
					.min(1, { message: "Password is required" }),
			})
			.parse(credentials);
		const admin = await Admin.findOne({ email: parsedCreds.email });
		if (!admin) {
			logger.warn(`Admin login failed: ${parsedCreds.email} not found.`);
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}
		const isMatch = await bcrypt.compare(
			parsedCreds.password,
			admin.password
		);
		if (!isMatch) {
			logger.warn(
				`Admin login failed: Incorrect password for ${parsedCreds.email}`
			);
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}

		// If admin has enabled two-factor auth, send OTP and do not complete login.
		if (admin.twoFactorEnabled) {
			const otp = Math.floor(100000 + Math.random() * 900000).toString();
			admin.twoFactorOTP = otp;
			admin.twoFactorOTPExpires = Date.now() + 5 * 60 * 1000;
			await admin.save();
			await sendAdminTwoFactorOTPEmail(admin.email, otp);
			logger.info(`2FA OTP sent for admin: ${admin._id}`);
			return sendResponse(
				res,
				200,
				true,
				{ twoFactorRequired: true },
				"OTP sent, please verify your login via the two-factor endpoint."
			);
		}

		// If 2FA is not enabled, complete login.
		const token = generateAdminToken({ id: admin._id, email: admin.email });
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};
		res.cookie("admin-token", token, cookieOptions);

		await Session.create({
			user: admin._id,
			userModel: "Admin",
			...getSessionData(req, token),
		});

		logger.info(`Admin logged in: ${admin._id}`);
		return sendResponse(
			res,
			200,
			true,
			_.pick(admin, [
				"_id",
				"name",
				"email",
				"role",
				"accessLevel",
				"permissions",
			]),
			"Login successful"
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			logger.error("Validation error during admin login.");
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		logger.error(`Error in loginAdmin: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Validate admin token
export const validateAdminToken = async (req, res) => {
	try {
		let token;
		if (req.cookies && req.cookies["admin-token"]) {
			token = req.cookies["admin-token"];
		} else if (
			req.headers.authorization &&
			req.headers.authorization.startsWith("Bearer ")
		) {
			token = req.headers.authorization.split(" ")[1];
		}
		if (!token) {
			logger.warn("No token provided for admin validation.");
			return sendResponse(res, 401, false, null, "No token provided");
		}
		const decoded = verifyAdminToken(token);
		if (!decoded) {
			logger.warn("Invalid admin token provided.");
			return sendResponse(res, 401, false, null, "Invalid token");
		}
		logger.info(`Admin token validated: ${decoded.id}`);

		return sendResponse(res, 200, true, decoded, "Token is valid");
	} catch (err) {
		logger.error(`Error in validateAdminToken: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Logout admin
export const logoutAdmin = async (req, res) => {
	try {
		res.clearCookie("admin-token");
		logger.info(
			`Admin logged out: ${req.admin ? req.admin.id : "unknown admin"}`
		);
		return sendResponse(res, 200, true, null, "Logged out successfully");
	} catch (err) {
		logger.error(`Error in logoutAdmin: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Retrieve admin profile (requires verified email)
export const getAdminProfile = async (req, res) => {
	try {
		const admin = await Admin.findById(req.admin.id).select("-password");
		if (!admin) {
			logger.warn(
				`Admin not found for profile retrieval: ${req.admin.id}`
			);
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		if (!admin.isVerified) {
			return sendResponse(
				res,
				403,
				false,
				null,
				"Your email is not verified. Please verify your email to access your profile."
			);
		}
		logger.info(`Admin profile retrieved: ${req.admin.id}`);
		return sendResponse(res, 200, true, admin, "Admin profile retrieved");
	} catch (err) {
		logger.error(`Error in getAdminProfile: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Update admin profile (requires verified email)
export const updateAdminProfile = async (req, res) => {
	try {
		const existingAdmin = await Admin.findById(req.admin.id);
		if (!existingAdmin) {
			logger.warn(`Admin not found for update: ${req.admin.id}`);
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		if (!existingAdmin.isVerified) {
			return sendResponse(
				res,
				403,
				false,
				null,
				"Your email is not verified. Please verify your email to update your profile."
			);
		}

		const allowedFields = [
			"name",
			"email",
			"password",
			"dateOfBirth",
			"emergencyRecoveryContact",
			"role",
			"permissions",
			"accessLevel",
		];
		const updateData = _.pick(req.body, allowedFields);
		if (updateData.password) {
			const salt = await bcrypt.genSalt(10);
			updateData.password = await bcrypt.hash(updateData.password, salt);
		}
		const admin = await Admin.findByIdAndUpdate(req.admin.id, updateData, {
			new: true,
		});
		if (!admin) {
			logger.warn(`Admin not found for update: ${req.admin.id}`);
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		logger.info(`Admin profile updated: ${req.admin.id}`);
		return sendResponse(
			res,
			200,
			true,
			_.pick(admin, [
				"_id",
				"name",
				"email",
				"role",
				"accessLevel",
				"permissions",
			]),
			"Admin profile updated successfully"
		);
	} catch (err) {
		logger.error(`Error in updateAdminProfile: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Delete admin account (requires verified email)
export const deleteAdminAccount = async (req, res) => {
	try {
		const existingAdmin = await Admin.findById(req.admin.id);
		if (!existingAdmin) {
			logger.warn(`Admin not found for deletion: ${req.admin.id}`);
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		if (!existingAdmin.isVerified) {
			return sendResponse(
				res,
				403,
				false,
				null,
				"Your email is not verified. Please verify your email to delete your account."
			);
		}
		await Admin.findByIdAndDelete(req.admin.id);
		logger.info(`Admin account deleted: ${req.admin.id}`);
		return sendResponse(
			res,
			200,
			true,
			null,
			"Admin account deleted successfully"
		);
	} catch (err) {
		logger.error(`Error in deleteAdminAccount: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
