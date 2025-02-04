import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
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
		dateOfBirth: {
			type: Date,
		},
		lastActive: {
			type: Date,
		},
		emergencyRecoveryContact: {
			type: String,
		},
		isAdmin: {
			type: Boolean,
			default: false,
		},
		// New fields for email verification
		isVerified: {
			type: Boolean,
			default: false,
		},
		emailVerificationToken: String,
		emailVerificationExpires: Date,
		// New fields for password reset
		forgotPasswordToken: String,
		forgotPasswordExpires: Date,
		// Two-Factor Authentication fields
		twoFactorEnabled: {
			type: Boolean,
			default: false,
		},
		twoFactorOTP: String,
		twoFactorOTPExpires: Date,
	},
	{ timestamps: true, collection: "users" }
);

export default mongoose.model("User", userSchema);
