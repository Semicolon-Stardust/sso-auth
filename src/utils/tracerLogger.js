// src/utils/tracerLogger.js
import tracer from "tracer";

const tracerLogger = tracer.console({
	format: "{{timestamp}} <{{title}}> {{message}} (in {{file}}:{{line}})",
	dateformat: "HH:MM:ss.L",
});

export default tracerLogger;
