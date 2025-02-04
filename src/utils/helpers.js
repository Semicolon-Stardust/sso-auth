// src/utils/helpers.js
export const sendResponse = (
	res,
	statusCode,
	success,
	data = null,
	message = ""
) => {
	return res.status(statusCode).json({ success, data, message });
};

export const formatError = (errors) => {
	return errors.map((err) => ({ field: err.path, message: err.message }));
};
