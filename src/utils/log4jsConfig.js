// src/utils/log4jsConfig.js
import log4js from "log4js";

log4js.configure({
	appenders: {
		console: { type: "console" },
		file: { type: "file", filename: "logs/app.log" },
	},
	categories: {
		default: { appenders: ["console", "file"], level: "info" },
		auth: { appenders: ["console", "file"], level: "debug" },
	},
});

export const logger = log4js.getLogger(); // default logger
export const authLogger = log4js.getLogger("auth"); // logger for authentication flows
