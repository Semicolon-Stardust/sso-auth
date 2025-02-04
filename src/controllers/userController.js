// src/controllers/userController.js
import { z } from "zod";
import User from "../models/User.js";
import Session from "../models/Session.js";
import bcrypt from "bcryptjs";
import { generateToken, verifyToken } from "../services/tokenServices.js";
import { sendResponse, formatError } from "../utils/helpers.js";

// Validation schema for user registration
const userRegisterSchema = z.object({
	name: z.string().min(1, { message: "Name is required" }),
	email: z.string().email({ message: "Invalid email format" }),
	password: z
		.string()
		.min(6, { message: "Password must be at least 6 characters long" }),
	confirmPassword: z
		.string()
		.min(6, {
			message: "Confirm password must be at least 6 characters long",
		}),
	dateOfBirth: z.string().optional(),
	emergencyRecoveryContact: z.string().optional(),
});

// Validation schema for user login
const userLoginSchema = z.object({
	email: z.string().email({ message: "Invalid email format" }),
	password: z.string().min(1, { message: "Password is required" }),
});

// Helper to extract session data from the request
const getSessionData = (req, token) => ({
	ipAddress:
		req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown",
	location: "Unknown", // Optionally, integrate geolocation here
	userAgent: req.headers["user-agent"] || "Unknown",
	token,
});

// Register new user
export const registerUser = async (req, res) => {
	try {
		const parsedData = userRegisterSchema.parse(req.body);
		const {
			name,
			email,
			password,
			confirmPassword,
			dateOfBirth,
			emergencyRecoveryContact,
		} = parsedData;

		if (password !== confirmPassword) {
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}

		let user = await User.findOne({ email });
		if (user) {
			return sendResponse(res, 400, false, null, "User already exists");
		}

		// Hash the password
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		user = await User.create({
			name,
			email,
			password: hashedPassword,
			dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined,
			emergencyRecoveryContact,
		});

		const token = generateToken({
			id: user._id,
			email: user.email,
			isAdmin: user.isAdmin,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000, // 1 hour
		};

		res.cookie("token", token, cookieOptions);

		// Record session details
		await Session.create({
			user: user._id,
			userModel: "User",
			...getSessionData(req, token),
		});

		return sendResponse(
			res,
			201,
			true,
			{
				user: { id: user._id, name: user.name, email: user.email },
				token,
			},
			"User registered successfully"
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Login user
export const loginUser = async (req, res) => {
	try {
		const { email, password } = userLoginSchema.parse(req.body);
		const user = await User.findOne({ email });
		if (!user) {
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}

		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}

		const token = generateToken({
			id: user._id,
			email: user.email,
			isAdmin: user.isAdmin,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};

		res.cookie("token", token, cookieOptions);

		await Session.create({
			user: user._id,
			userModel: "User",
			...getSessionData(req, token),
		});

		return sendResponse(
			res,
			200,
			true,
			{
				user: { id: user._id, name: user.name, email: user.email },
				token,
			},
			"Login successful"
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Validate user token
export const validateUserToken = async (req, res) => {
	try {
		let token;
		if (req.cookies && req.cookies.token) {
			token = req.cookies.token;
		} else if (
			req.headers.authorization &&
			req.headers.authorization.startsWith("Bearer ")
		) {
			token = req.headers.authorization.split(" ")[1];
		}
		if (!token) {
			return sendResponse(res, 401, false, null, "No token provided");
		}
		const decoded = verifyToken(token);
		if (!decoded) {
			return sendResponse(res, 401, false, null, "Invalid token");
		}
		return sendResponse(res, 200, true, decoded, "Token is valid");
	} catch (err) {
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Logout user
export const logoutUser = async (req, res) => {
	try {
		res.clearCookie("token");
		return sendResponse(res, 200, true, null, "Logged out successfully");
	} catch (err) {
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
