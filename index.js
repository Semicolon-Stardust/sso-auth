import app from './src/app.js'
import dotenv from 'dotenv';
import connectDB from './src/config/db.js';

dotenv.config();

const SERVER_PORT = process.env.SERVER_PORT || 6000;

process.on("uncaughtException", err => {
    console.log(`Error: ${err.message}`);
    console.log("Shutting down the server due to Uncaught Exception");
    process.exit(1);
})

connectDB();

app.listen(SERVER_PORT, () => {
    console.log(`Server running on port http://localhost:${SERVER_PORT}/`);
})

process.on("unhandledRejection", err => {
    console.log(`Error: ${err.message}`);
    console.log("Shutting down the server due to Unhandled Promise Rejection");
    server.close(() => {
        process.exit(1);
    });
})