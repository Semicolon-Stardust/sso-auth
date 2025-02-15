// src/services/tokenServices.js
import jwt from "jsonwebtoken";

// Admin token functions
export const generateAdminToken = (payload) => {
	return jwt.sign(payload, process.env.ADMIN_JWT_SECRET, { expiresIn: "1h" });
};

export const verifyAdminToken = (token) => {
	try {
		return jwt.verify(token, process.env.ADMIN_JWT_SECRET);
	} catch (error) {
		return null;
	}
};

// User token functions
export const generateUserToken = (payload) => {
	return jwt.sign(payload, process.env.USER_JWT_SECRET, { expiresIn: "1h" });
};

export const verifyUserToken = (token) => {
	try {
		return jwt.verify(token, process.env.USER_JWT_SECRET);
	} catch (error) {
		return null;
	}
};
