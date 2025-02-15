// src/models/Admin.js
import mongoose from "mongoose";

const adminSchema = new mongoose.Schema(
	{
		name: {
			type: String,
			required: [true, "Name is required"],
		},
		email: {
			type: String,
			required: [true, "Email is required"],
			unique: true,
			lowercase: true,
			trim: true,
		},
		password: {
			type: String,
			required: [true, "Password is required"],
		},
		// "confirmPassword" is not stored; it’s only for validation on registration.
		adminKey: {
			type: String,
			// Compare with process.env.ADMIN_KEY in the controller.
		},
		role: {
			type: String,
			enum: ["Admin", "Super Admin", "Moderator"],
			required: true,
		},
		permissions: {
			type: [String],
			default: [],
		},
		accessLevel: {
			type: Number,
			min: 1,
			max: 5,
			default: 5,
		},
		adminCreatedBy: {
			type: String, // Stores the ID or email of the creator
		},
		adminCreatedOn: {
			type: Date,
			default: Date.now,
		},
		lastActive: {
			type: Date,
		},
		dateOfBirth: {
			type: Date,
		},
		canManageUsers: {
			type: Boolean,
			default: false,
		},
		canManageContent: {
			type: Boolean,
			default: false,
		},
		canManagePayments: {
			type: Boolean,
			default: false,
		},
		canViewReports: {
			type: Boolean,
			default: false,
		},
		canApproveNewAdmins: {
			type: Boolean,
			default: false,
		},
		canSuspendUsers: {
			type: Boolean,
			default: false,
		},
		canDeleteData: {
			type: Boolean,
			default: false,
		},
		canExportData: {
			type: Boolean,
			default: false,
		},
		superAdminKey: {
			type: String,
			// Validate against process.env.SUPER_ADMIN_KEY in the controller.
		},
		canPromoteDemoteAdmins: {
			type: Boolean,
			default: false,
		},
		canModifyAdminPermissions: {
			type: Boolean,
			default: false,
		},
		canOverrideSecuritySettings: {
			type: Boolean,
			default: false,
		},
		emergencyRecoveryContact: {
			type: String,
		},
	},
	{ timestamps: true, collection: "admins" }
);

export default mongoose.model("Admin", adminSchema);
