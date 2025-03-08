// src/routes/cowRoutes.js
import { Router } from "express";
import {
	getCows,
	getCowById,
	createCow,
	updateCow,
	deleteCow,
} from "../controllers/cowController.js";
import { adminProtect } from "../middlewares/authMiddleware.js";

const router = Router();

// Public routes
router.get("/", getCows);
router.get("/:id", getCowById);

// Admin routes (protected with ssoAdminAuth)
router.post("/admin/cows", adminProtect, createCow);
router.put("/admin/cows/:id", adminProtect, updateCow);
router.delete("/admin/cows/:id", adminProtect, deleteCow);

export default router;
