// src/app.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import dotenv from "dotenv";
import userRoutes from "./router/userRoutes.js";
import adminRoutes from "./router/adminRoutes.js";
import userExtraRoutes from "./router/userExtraRoutes.js";

dotenv.config();

const app = express();
const CLIENT_PORT = process.env.CLIENT_PORT || 8000;
const API_VERSION = process.env.VERSION || "1";

// Secure the app with Helmet
app.use(helmet());

// Log incoming HTTP requests with Morgan
app.use(morgan("combined"));

// Parse JSON and URL-encoded data, and cookies
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Mount routes (with dynamic versioning)
app.use(userRoutes(API_VERSION));
app.use(adminRoutes(API_VERSION));
app.use(userExtraRoutes(API_VERSION));

// Health check route
app.get("/", (req, res) => {
	res.send("Welcome to the Authentication API");
});

export default app;
