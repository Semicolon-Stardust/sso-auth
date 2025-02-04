// src/routes/userRoutes.js
import { Router } from "express";
import { registerUser, loginUser, validateUserToken, logoutUser } from "../controllers/userController.js";
import { loginLimiter } from "../middlewares/rateLimiter.js";

export default function userRoutes(version) {
  const router = Router();

  router.post(`/api/v${version}/auth/register`, registerUser);
  router.post(`/api/v${version}/auth/login`, loginLimiter, loginUser);
  router.get(`/api/v${version}/auth/validate-token`, validateUserToken);
  router.post(`/api/v${version}/auth/logout`, logoutUser);

  return router;
}
