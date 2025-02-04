// src/app.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import userRoutes from "./router/userRoutes.js";
import adminRoutes from "./router/adminRoutes.js";
import userExtraRoutes from './router/userExtraRoutes.js';

dotenv.config();

const app = express();

const CLIENT_PORT = process.env.CLIENT_PORT || 8000;
const API_VERSION = process.env.VERSION || "1";

const corsOptions = {
	origin: `http://localhost:${CLIENT_PORT}`,
	optionsSuccessStatus: 200,
};

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors(corsOptions));
app.use(cookieParser());

// Mount routes (with dynamic versioning)
app.use(userRoutes(API_VERSION));
app.use(adminRoutes(API_VERSION));

// Mount extra user routes
app.use(userExtraRoutes(API_VERSION));

// Optional: Base route for health check
app.get("/", (req, res) => {
	res.send("Welcome to the Authentication API");
});

export default app;
