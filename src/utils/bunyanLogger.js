// src/utils/bunyanLogger.js
import bunyan from "bunyan";

const bunyanLogger = bunyan.createLogger({
	name: "SSOAuthSystem",
	level: "info",
});

export default bunyanLogger;
