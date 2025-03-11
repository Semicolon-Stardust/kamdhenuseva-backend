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
import upload from "../middlewares/uploadMiddleware.js";

const router = Router();

// Public routes
router.get("/", getCows);
router.get("/:id", getCowById);

// Admin routes (protected with adminProtect)
// Change from upload.single("image") to upload.array("images")
router.post("/admin/cows", adminProtect, upload.array("images"), createCow);
router.put("/admin/cows/:id", adminProtect, upload.array("images"), updateCow);
router.delete("/admin/cows/:id", adminProtect, deleteCow);

export default router;
