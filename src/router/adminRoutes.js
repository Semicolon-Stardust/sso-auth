// src/routes/adminRoutes.js
import { Router } from "express";
import { registerAdmin, loginAdmin, validateAdminToken, logoutAdmin } from "../controllers/adminController.js";
import { loginLimiter } from "../middlewares/rateLimiter.js";

export default function adminRoutes(version) {
  const router = Router();

  router.post(`/api/v${version}/admin/register`, registerAdmin);
  router.post(`/api/v${version}/admin/login`, loginLimiter, loginAdmin);
  router.get(`/api/v${version}/admin/validate-token`, validateAdminToken);
  router.post(`/api/v${version}/admin/logout`, logoutAdmin);

  return router;
}
