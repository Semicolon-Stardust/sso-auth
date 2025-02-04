import { Router } from "express";
import {
	registerAdmin,
	loginAdmin,
	validateAdminToken,
	logoutAdmin,
	getAdminProfile,
	updateAdminProfile,
	deleteAdminAccount,
} from "../controllers/adminController.js";
import { loginLimiter } from "../middlewares/rateLimiter.js";
import { protect } from "../middlewares/authMiddleware.js";

export default function adminRoutes(version) {
	const router = Router();

	// Authentication endpoints
	router.post(`/api/v${version}/admin/register`, registerAdmin);
	router.post(`/api/v${version}/admin/login`, loginLimiter, loginAdmin);
	router.get(`/api/v${version}/admin/validate-token`, validateAdminToken);
	router.post(`/api/v${version}/admin/logout`, logoutAdmin);

	// CRUD endpoints for admin profile
	router.get(`/api/v${version}/admin/profile`, protect, getAdminProfile);
	router.put(
		`/api/v${version}/admin/update-profile`,
		protect,
		updateAdminProfile
	);
	router.delete(
		`/api/v${version}/admin/delete-account`,
		protect,
		deleteAdminAccount
	);

	return router;
}
