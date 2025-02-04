import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

export default async function connectDB() {
	try {
		const conn = await mongoose.connect(
			process.env.ENVIRONMENT === "Development"
				? process.env.MONGO_URI
				: `${process.env.MONGO_URI}/production`
		);
		console.log(`MongoDB Connected: ${conn.connection.host}`);
	} catch (error) {
		console.error(`Error connecting to MongoDB: ${error.message}`);
		process.exit(1);
	}
}
