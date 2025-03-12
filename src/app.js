// src/app.js

// Import external modules
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import dotenv from "dotenv";

// Import route modules which provide user and admin API endpoints
import userRoutes from "./routes/userRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import userExtraRoutes from "./routes/userExtraRoutes.js";
import adminExtraRoutes from "./routes/adminExtraRoutes.js";
import cowRoutes from "./routes/cowRoutes.js";
import donationRoutes from "./routes/donationRoutes.js";

// Load environment variables from .env file
dotenv.config();

const app = express();

// Set up basic configuration with defaults:
// CLIENT_PORT for client origin, and API_VERSION for route versioning.

const API_VERSION = process.env.API_VERSION || "1";

// Enable CORS for requests from the client origin, allowing credentials.
app.use(
	cors({
		origin: `${process.env.CLIENT_URL}`,
		credentials: true,
	})
);

// Secure HTTP headers with Helmet.
app.use(helmet());

// Log incoming HTTP requests for debugging and monitoring with Morgan.
app.use(morgan("combined"));

// Parse JSON payloads, URL-encoded form data, and cookies.
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Mount routes with dynamic API versioning.
// User Routes: typically include login, registration etc.
// The actual base path is defined within the userRoutes module.
app.use(userRoutes(API_VERSION));

// Admin Routes: handle administrative functions.
// The route prefix is dynamically added inside the adminRoutes module.
app.use(adminRoutes(API_VERSION));

// Additional User Routes: supplementary endpoints for user-related operations.
app.use(userExtraRoutes(API_VERSION));

// Additional Admin Routes: supplementary endpoints for admin-specific operations.
app.use(adminExtraRoutes(API_VERSION));
app.use(`/api/v${API_VERSION}/cows`, cowRoutes);
app.use(`/api/v${API_VERSION}/donations`, donationRoutes);

// Health Check Route:
// GET / returns a simple message to verify that the server is running.
app.get("/", (req, res) => {
	res.send("Welcome to the Authentication API");
});

export default app;
