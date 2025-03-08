// src/routes/donationRoutes.js
import { Router } from "express";
import {
	createDonation,
	getDonationHistory,
	getAllDonations,
} from "../controllers/donationController.js";
import { adminProtect, userProtect } from "../middlewares/authMiddleware.js";

const router = Router();

// Routes for authenticated users
router.post("/", userProtect, createDonation);
router.get("/history", userProtect, getDonationHistory);

// Admin-only route for viewing all donations
router.get("/admin/all", adminProtect, getAllDonations);

export default router;
