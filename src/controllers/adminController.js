// src/controllers/adminController.js
import { z } from "zod";
import Admin from "../models/Admin.js";
import Session from "../models/Session.js";
import bcrypt from "bcryptjs";
import { generateToken, verifyToken } from "../services/tokenServices.js";
import { sendResponse, formatError } from "../utils/helpers.js";

// Validation schema for admin registration
const adminRegisterSchema = z.object({
	name: z.string().min(1, { message: "Name is required" }),
	email: z.string().email({ message: "Invalid email format" }),
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
	// Optional boolean flags (defaults will be applied)
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

// Validation schema for admin login
const adminLoginSchema = z.object({
	email: z.string().email({ message: "Invalid email format" }),
	password: z.string().min(1, { message: "Password is required" }),
});

// Helper to extract session data
const getSessionData = (req, token) => ({
	ipAddress:
		req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown",
	location: "Unknown",
	userAgent: req.headers["user-agent"] || "Unknown",
	token,
});

// Register new admin
export const registerAdmin = async (req, res) => {
	try {
		const parsedData = adminRegisterSchema.parse(req.body);
		const {
			name,
			email,
			password,
			confirmPassword,
			adminKey,
			role,
			permissions,
			accessLevel,
			dateOfBirth,
			emergencyRecoveryContact,
			canManageUsers,
			canManageContent,
			canManagePayments,
			canViewReports,
			canApproveNewAdmins,
			canSuspendUsers,
			canDeleteData,
			canExportData,
			superAdminKey,
			canPromoteDemoteAdmins,
			canModifyAdminPermissions,
			canOverrideSecuritySettings,
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

		// Validate provided admin keys against environment variables
		if (role !== "Super Admin" && adminKey !== process.env.ADMIN_KEY) {
			return sendResponse(res, 401, false, null, "Invalid admin key");
		}
		if (
			role === "Super Admin" &&
			superAdminKey !== process.env.SUPER_ADMIN_KEY
		) {
			return sendResponse(
				res,
				401,
				false,
				null,
				"Invalid super admin key"
			);
		}

		let admin = await Admin.findOne({ email });
		if (admin) {
			return sendResponse(res, 400, false, null, "Admin already exists");
		}

		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		admin = await Admin.create({
			name,
			email,
			password: hashedPassword,
			adminKey,
			role,
			permissions: permissions || [],
			accessLevel: accessLevel || 5,
			dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined,
			emergencyRecoveryContact,
			canManageUsers: canManageUsers || false,
			canManageContent: canManageContent || false,
			canManagePayments: canManagePayments || false,
			canViewReports: canViewReports || false,
			canApproveNewAdmins: canApproveNewAdmins || false,
			canSuspendUsers: canSuspendUsers || false,
			canDeleteData: canDeleteData || false,
			canExportData: canExportData || false,
			superAdminKey: superAdminKey || null,
			canPromoteDemoteAdmins: canPromoteDemoteAdmins || false,
			canModifyAdminPermissions: canModifyAdminPermissions || false,
			canOverrideSecuritySettings: canOverrideSecuritySettings || false,
		});

		// Optionally, record adminCreatedBy information if available

		const token = generateToken({
			id: admin._id,
			email: admin.email,
			isAdmin: admin.isAdmin,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};

		res.cookie("token", token, cookieOptions);

		await Session.create({
			user: admin._id,
			userModel: "Admin",
			...getSessionData(req, token),
		});

		return sendResponse(
			res,
			201,
			true,
			{
				admin: {
					id: admin._id,
					name: admin.name,
					email: admin.email,
					role: admin.role,
				},
				token,
			},
			"Admin registered successfully"
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

// Login admin
export const loginAdmin = async (req, res) => {
	try {
		const { email, password } = adminLoginSchema.parse(req.body);
		const admin = await Admin.findOne({ email });
		if (!admin) {
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}

		const isMatch = await bcrypt.compare(password, admin.password);
		if (!isMatch) {
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}

		const token = generateToken({
			id: admin._id,
			email: admin.email,
			isAdmin: admin.isAdmin,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};

		res.cookie("token", token, cookieOptions);

		await Session.create({
			user: admin._id,
			userModel: "Admin",
			...getSessionData(req, token),
		});

		return sendResponse(
			res,
			200,
			true,
			{
				admin: {
					id: admin._id,
					name: admin.name,
					email: admin.email,
					role: admin.role,
				},
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

// Validate admin token
export const validateAdminToken = async (req, res) => {
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

// Logout admin
export const logoutAdmin = async (req, res) => {
	try {
		res.clearCookie("token");
		return sendResponse(res, 200, true, null, "Logged out successfully");
	} catch (err) {
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Retrieve the profile of the logged-in admin
export const getAdminProfile = async (req, res) => {
	try {
		const admin = await Admin.findById(req.user.id).select("-password");
		if (!admin) {
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		return sendResponse(res, 200, true, admin, "Admin profile retrieved");
	} catch (err) {
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Update the profile of the logged-in admin
export const updateAdminProfile = async (req, res) => {
	try {
		const updateData = req.body;

		// Hash the password if it is provided for update
		if (updateData.password) {
			const salt = await bcrypt.genSalt(10);
			updateData.password = await bcrypt.hash(updateData.password, salt);
		}

		const admin = await Admin.findByIdAndUpdate(req.user.id, updateData, {
			new: true,
		});
		if (!admin) {
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		return sendResponse(
			res,
			200,
			true,
			admin,
			"Admin profile updated successfully"
		);
	} catch (err) {
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Delete the logged-in admin's account
export const deleteAdminAccount = async (req, res) => {
	try {
		await Admin.findByIdAndDelete(req.user.id);
		return sendResponse(
			res,
			200,
			true,
			null,
			"Admin account deleted successfully"
		);
	} catch (err) {
		console.error(err);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
