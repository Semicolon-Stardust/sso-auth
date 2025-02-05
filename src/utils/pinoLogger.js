// src/utils/pinoLogger.js
import pino from "pino";

const pinoLogger = pino({
	level: process.env.LOG_LEVEL || "info",
	transport: {
		target: "pino-pretty",
		options: {
			colorize: true,
			translateTime: "SYS:standard", // optional: formats the timestamp
		},
	},
});

export default pinoLogger;
