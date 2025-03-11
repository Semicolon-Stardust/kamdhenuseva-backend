// src/controllers/cowController.js
import Cow from "../models/Cow.js";
import { uploadFileToR2 } from "../services/r2Service.js";

/**
 * Create Cow(s)
 * If req.body.data exists (sent as a JSON string), parse it.
 * If req.files exist, upload each file and store the resulting URLs in the 'photos' field.
 */
// src/controllers/cowController.js
export const createCow = async (req, res) => {
	try {
		let bodyData = req.body;
		if (req.body.data) {
			try {
				bodyData = JSON.parse(req.body.data);
			} catch (parseError) {
				console.error(
					"Error parsing JSON from req.body.data:",
					parseError
				);
				return res
					.status(400)
					.json({ error: "Invalid JSON data format" });
			}
		}

		let photoUrls = [];
		if (req.files && req.files.length > 0) {
			for (const file of req.files) {
				const fileName = `${file.originalname}_${Date.now()}`;
				try {
					const url = await uploadFileToR2(
						file.buffer,
						fileName,
						file.mimetype
					);
					photoUrls.push(url);
				} catch (uploadError) {
					console.error("Error uploading file:", uploadError);
					return res
						.status(500)
						.json({ error: "File upload failed" });
				}
			}
		}

		if (Array.isArray(bodyData)) {
			const cowsData = bodyData.map((item) => ({
				...item,
				photos: photoUrls.length
					? photoUrls
					: item.photo
					? [item.photo]
					: [],
			}));
			const cows = await Cow.insertMany(cowsData);
			return res.status(201).json({ data: cows });
		} else {
			const cowData = {
				...bodyData,
				photos: photoUrls.length
					? photoUrls
					: bodyData.photo
					? [bodyData.photo]
					: [],
			};
			const cow = new Cow(cowData);
			await cow.save();
			return res.status(201).json({ data: cow });
		}
	} catch (error) {
		console.error("createCow error:", error);
		return res.status(500).json({ error: error.message });
	}
};

/**
 * Get Cows with search, filtering, sorting, and pagination.
 * Query parameters:
 * - page: Page number (default: 1)
 * - limit: Items per page (default: 20)
 * - sort: Field to sort by (default: "name")
 * - name: (optional) Search cows by name (case-insensitive)
 * - sick: (optional) "true" or "false" to filter by sicknessStatus
 * - old: (optional) "true" or "false" to filter by agedStatus
 * - adopted: (optional) "true" or "false" to filter by adoptionStatus
 * - gender: (optional) "Male" or "Female" to filter by gender
 */
export const getCows = async (req, res) => {
	try {
		const page = parseInt(req.query.page) || 1;
		const limit = parseInt(req.query.limit) || 20;
		const sort = req.query.sort || "name";
		const skip = (page - 1) * limit;

		// Constructing search and filter query
		let filter = {};

		if (req.query.name) {
			filter.name = { $regex: req.query.name, $options: "i" };
		}
		if (req.query.sick) {
			filter.sicknessStatus = req.query.sick === "true";
		}
		if (req.query.old) {
			filter.agedStatus = req.query.old === "true";
		}
		if (req.query.adopted) {
			filter.adoptionStatus = req.query.adopted === "true";
		}
		if (req.query.gender) {
			filter.gender = req.query.gender;
		}

		// Fetch total count
		const total = await Cow.countDocuments(filter);
		const cows = await Cow.find(filter).sort(sort).skip(skip).limit(limit);

		return res.json({
			data: cows,
			pagination: {
				total,
				page,
				pages: Math.ceil(total / limit),
			},
		});
	} catch (error) {
		return res.status(500).json({ error: error.message });
	}
};

/**
 * Get a specific cow by ID.
 */
export const getCowById = async (req, res) => {
	try {
		const cow = await Cow.findById(req.params.id);
		if (!cow) return res.status(404).json({ error: "Cow not found" });
		return res.json({ data: cow });
	} catch (error) {
		return res.status(500).json({ error: error.message });
	}
};

export const updateCow = async (req, res) => {
	try {
		// Parse JSON data if sent under the key "data"
		let bodyData = req.body;
		if (req.body.data) {
			try {
				bodyData = JSON.parse(req.body.data);
			} catch (parseError) {
				console.error("Error parsing JSON in updateCow:", parseError);
				return res.status(400).json({ error: "Invalid JSON data" });
			}
		}

		// Process uploaded files, if any
		let photoUrls = [];
		if (req.files && req.files.length > 0) {
			for (const file of req.files) {
				const fileName = `${Date.now()}_${file.originalname}`;
				try {
					const url = await uploadFileToR2(
						file.buffer,
						fileName,
						file.mimetype
					);
					photoUrls.push(url);
				} catch (uploadError) {
					console.error(
						"Error uploading file in updateCow:",
						uploadError
					);
					return res
						.status(500)
						.json({ error: "File upload failed" });
				}
			}
			// Optionally, update the 'photos' field with new URLs.
			// This example replaces existing images. Adjust if you want to merge.
			bodyData.photos = photoUrls;
		}

		// Update the cow document using the final data
		const cow = await Cow.findByIdAndUpdate(req.params.id, bodyData, {
			new: true,
		});
		if (!cow) return res.status(404).json({ error: "Cow not found" });
		return res.json({ data: cow });
	} catch (error) {
		console.error("updateCow error:", error);
		return res.status(500).json({ error: error.message });
	}
};

/**
 * Delete a cow by ID.
 */
export const deleteCow = async (req, res) => {
	try {
		const cow = await Cow.findByIdAndDelete(req.params.id);
		if (!cow) return res.status(404).json({ error: "Cow not found" });
		return res.json({ message: "Cow deleted successfully" });
	} catch (error) {
		return res.status(500).json({ error: error.message });
	}
};
