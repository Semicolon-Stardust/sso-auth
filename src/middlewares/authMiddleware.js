// src/middlewares/authMiddleware.js
import { verifyToken } from "../services/tokenServices.js";

export const protect = (req, res, next) => {
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
		return res
			.status(401)
			.json({ success: false, message: "No token provided" });
	}
	const decoded = verifyToken(token);
	if (!decoded) {
		return res
			.status(401)
			.json({ success: false, message: "Invalid token" });
	}
	req.user = decoded;
	next();
};
