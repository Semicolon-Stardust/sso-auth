// src/controllers/userController.js

import bcrypt from "bcryptjs";
import _ from "lodash";
import { z } from "zod";
import crypto from "crypto"; // NEW: to generate a verification token
import User from "../models/User.js";
import Session from "../models/Session.js";
import {
	generateUserToken,
	verifyUserToken,
} from "../services/tokenServices.js";
import { sendResponse, formatError } from "../utils/helpers.js";
import { sendVerificationEmail } from "../services/emailService.js"; // NEW: to send email


// Use only one logger (Winston)
import logger from "../utils/logger.js";

// -----------------------------------------------------
// Zod Schemas for User Registration and Login
// -----------------------------------------------------

const userRegisterSchema = z.object({
	name: z.string().min(1, { message: "Name is required" }),
	email: z.string().email({ message: "Invalid email format" }),
	password: z
		.string()
		.min(6, { message: "Password must be at least 6 characters long" }),
	confirmPassword: z.string().min(6, {
		message: "Confirm password must be at least 6 characters long",
	}),
	dateOfBirth: z.string().optional(),
	emergencyRecoveryContact: z.string().optional(),
});

const userLoginSchema = z.object({
	email: z.string().email({ message: "Invalid email format" }),
	password: z.string().min(1, { message: "Password is required" }),
});

// -----------------------------------------------------
// Helper: Extract Session Data
// -----------------------------------------------------

const getSessionData = (req, token) => ({
	ipAddress:
		req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown",
	location: "Unknown", // Optionally integrate geolocation here
	userAgent: req.headers["user-agent"] || "Unknown",
	token,
});

// -----------------------------------------------------
// Controller Functions for Users
// -----------------------------------------------------

// Register new user
export const registerUser = async (req, res) => {
	try {
		const allowedFields = [
			"name",
			"email",
			"password",
			"confirmPassword",
			"dateOfBirth",
			"emergencyRecoveryContact",
		];
		const data = _.pick(req.body, allowedFields);

		// Validate input with Zod
		const parsedData = userRegisterSchema.parse(data);

		// Check if passwords match
		if (parsedData.password !== parsedData.confirmPassword) {
			logger.warn("Registration failed: Passwords do not match.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}
		delete parsedData.confirmPassword;

		// Check if user already exists
		let user = await User.findOne({ email: parsedData.email });
		if (user) {
			logger.warn(
				`User registration failed: ${parsedData.email} already exists.`
			);
			return sendResponse(res, 400, false, null, "User already exists");
		}

		// Hash password
		const salt = await bcrypt.genSalt(10);
		parsedData.password = await bcrypt.hash(parsedData.password, salt);

		// Create user
		user = await User.create(parsedData);

		// --- NEW: Generate verification token, update user, and send verification email ---
		const verificationToken = crypto.randomBytes(20).toString("hex");
		user.emailVerificationToken = verificationToken;
		user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours expiry
		await user.save();
		await sendVerificationEmail(user.email, verificationToken);
		// -----------------------------------------------------------------------------

		// Generate JWT token for login
		const token = generateUserToken({
			id: user._id,
			email: user.email,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000, // 1 hour
		};
		res.cookie("user-token", token, cookieOptions);

		// Create session record
		await Session.create({
			user: user._id,
			userModel: "User",
			...getSessionData(req, token),
		});

		logger.info(`User registered: ${user._id}`);

		return sendResponse(
			res,
			201,
			true,
			_.pick(user, [
				"_id",
				"name",
				"email",
				"dateOfBirth",
				"emergencyRecoveryContact",
			]),
			"User registered successfully. Please verify your email."
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			logger.error("Validation error during user registration.");
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		logger.error(`Error in registerUser: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Login user
export const loginUser = async (req, res) => {
	try {
		const credentials = _.pick(req.body, ["email", "password"]);
		const parsedCreds = userLoginSchema.parse(credentials);
		const user = await User.findOne({ email: parsedCreds.email });
		if (!user) {
			logger.warn(`Login failed: User ${parsedCreds.email} not found.`);
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}
		const isMatch = await bcrypt.compare(
			parsedCreds.password,
			user.password
		);
		if (!isMatch) {
			logger.warn(
				`Login failed: Incorrect password for ${parsedCreds.email}.`
			);
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}

		// Generate JWT token
		const token = generateUserToken({
			id: user._id,
			email: user.email,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};
		res.cookie("user-token", token, cookieOptions);

		await Session.create({
			user: user._id,
			userModel: "User",
			...getSessionData(req, token),
		});

		logger.info(`User logged in: ${user._id}`);

		return sendResponse(
			res,
			200,
			true,
			_.pick(user, [
				"_id",
				"name",
				"email",
				"dateOfBirth",
				"emergencyRecoveryContact",
			]),
			"Login successful"
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			logger.error("Validation error during user login.");
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		logger.error(`Error in loginUser: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Validate user token
export const validateUserToken = async (req, res) => {
	try {
		let token;
		if (req.cookies && req.cookies["user-token"]) {
			token = req.cookies["user-token"];
		} else if (
			req.headers.authorization &&
			req.headers.authorization.startsWith("Bearer ")
		) {
			token = req.headers.authorization.split(" ")[1];
		}
		if (!token) {
			logger.warn("No token provided for user validation.");
			return sendResponse(res, 401, false, null, "No token provided");
		}
		const decoded = verifyUserToken(token);
		if (!decoded) {
			logger.warn("Invalid token provided for user.");
			return sendResponse(res, 401, false, null, "Invalid token");
		}
		logger.info("User token validated successfully");

		return sendResponse(res, 200, true, { token }, "Token is valid");
	} catch (err) {
		logger.error(`Error in validateUserToken: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Logout user
export const logoutUser = async (req, res) => {
	try {
		res.clearCookie("user-token");
		logger.info(
			`User logged out: ${req.user ? req.user.id : "unknown user"}`
		);
		return sendResponse(res, 200, true, null, "Logged out successfully");
	} catch (err) {
		logger.error(`Error in logoutUser: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Retrieve user profile (requires verified email)
export const getUserProfile = async (req, res) => {
	try {
		const user = await User.findById(req.user.id).select("-password");
		if (!user) {
			logger.warn(`User not found for profile retrieval: ${req.user.id}`);
			return sendResponse(res, 404, false, null, "User not found");
		}
		if (!user.isVerified) {
			return sendResponse(
				res,
				403,
				false,
				null,
				"Your email is not verified. Please verify your email to access your profile."
			);
		}
		logger.info(`User profile retrieved: ${req.user.id}`);
		return sendResponse(res, 200, true, user, "User profile retrieved");
	} catch (err) {
		logger.error(`Error in getUserProfile: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Update user profile (requires verified email)
export const updateUserProfile = async (req, res) => {
	try {
		const existingUser = await User.findById(req.user.id);
		if (!existingUser) {
			logger.warn(`User not found for update: ${req.user.id}`);
			return sendResponse(res, 404, false, null, "User not found");
		}
		if (!existingUser.isVerified) {
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
		];
		const updateData = _.pick(req.body, allowedFields);

		if (updateData.password) {
			const salt = await bcrypt.genSalt(10);
			updateData.password = await bcrypt.hash(updateData.password, salt);
		}

		const user = await User.findByIdAndUpdate(req.user.id, updateData, {
			new: true,
		});
		if (!user) {
			logger.warn(`User not found for update: ${req.user.id}`);
			return sendResponse(res, 404, false, null, "User not found");
		}
		logger.info(`User profile updated: ${req.user.id}`);
		return sendResponse(
			res,
			200,
			true,
			_.pick(user, [
				"_id",
				"name",
				"email",
				"dateOfBirth",
				"emergencyRecoveryContact",
			]),
			"User profile updated successfully"
		);
	} catch (err) {
		logger.error(`Error in updateUserProfile: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Delete user account (requires verified email)
export const deleteUserAccount = async (req, res) => {
	try {
		const existingUser = await User.findById(req.user.id);
		if (!existingUser) {
			logger.warn(`User not found for deletion: ${req.user.id}`);
			return sendResponse(res, 404, false, null, "User not found");
		}
		if (!existingUser.isVerified) {
			return sendResponse(
				res,
				403,
				false,
				null,
				"Your email is not verified. Please verify your email to delete your account."
			);
		}
		await User.findByIdAndDelete(req.user.id);
		logger.info(`User account deleted: ${req.user.id}`);
		return sendResponse(
			res,
			200,
			true,
			null,
			"User account deleted successfully"
		);
	} catch (err) {
		logger.error(`Error in deleteUserAccount: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
