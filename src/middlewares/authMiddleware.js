// src/middlewares/authMiddleware.js
import {
	verifyAdminToken,
	verifyUserToken,
} from "../services/tokenServices.js";

// Middleware to protect admin routes
export const adminProtect = (req, res, next) => {
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
		return res
			.status(401)
			.json({ success: false, message: "No admin token provided" });
	}
	const decoded = verifyAdminToken(token);
	if (!decoded) {
		return res
			.status(401)
			.json({ success: false, message: "Invalid admin token" });
	}
	req.admin = decoded;
	next();
};

// Middleware to protect user routes
export const userProtect = (req, res, next) => {
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
		return res
			.status(401)
			.json({ success: false, message: "No user token provided" });
	}
	const decoded = verifyUserToken(token);
	if (!decoded) {
		return res
			.status(401)
			.json({ success: false, message: "Invalid user token" });
	}
	req.user = decoded;
	next();
};
