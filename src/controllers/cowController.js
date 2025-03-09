import Cow from "../models/Cow.js";

/**
 * Create Cow(s)
 * If req.body is an array, bulk create cows.
 * Otherwise, create a single cow.
 */
export const createCow = async (req, res) => {
	try {
		if (Array.isArray(req.body)) {
			// Bulk creation using insertMany
			const cows = await Cow.insertMany(req.body);
			return res.status(201).json({ data: cows });
		} else {
			// Single cow creation
			const cow = new Cow(req.body);
			await cow.save();
			return res.status(201).json({ data: cow });
		}
	} catch (error) {
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

/**
 * Update a cow by ID.
 */
export const updateCow = async (req, res) => {
	try {
		const cow = await Cow.findByIdAndUpdate(req.params.id, req.body, {
			new: true,
		});
		if (!cow) return res.status(404).json({ error: "Cow not found" });
		return res.json({ data: cow });
	} catch (error) {
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
