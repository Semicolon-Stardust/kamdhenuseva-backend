// src/controllers/cowController.js
import Cow from "../models/Cow.js";
import { buildQuery } from "../utils/helpers.js";

export const createCow = async (req, res) => {
	try {
		const cow = new Cow(req.body);
		await cow.save();
		res.status(201).json({ data: cow });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

export const getCows = async (req, res) => {
	try {
		const page = parseInt(req.query.page) || 1;
		const limit = parseInt(req.query.limit) || 20;
		const sort = req.query.sort || "name";
		const filter = buildQuery(req.query);

		const skip = (page - 1) * limit;
		const total = await Cow.countDocuments(filter);
		const cows = await Cow.find(filter).sort(sort).skip(skip).limit(limit);

		res.json({
			data: cows,
			pagination: {
				total,
				page,
				pages: Math.ceil(total / limit),
			},
		});
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

export const getCowById = async (req, res) => {
	try {
		const cow = await Cow.findById(req.params.id);
		if (!cow) return res.status(404).json({ error: "Cow not found" });
		res.json({ data: cow });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

export const updateCow = async (req, res) => {
	try {
		const cow = await Cow.findByIdAndUpdate(req.params.id, req.body, {
			new: true,
		});
		if (!cow) return res.status(404).json({ error: "Cow not found" });
		res.json({ data: cow });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

export const deleteCow = async (req, res) => {
	try {
		const cow = await Cow.findByIdAndDelete(req.params.id);
		if (!cow) return res.status(404).json({ error: "Cow not found" });
		res.json({ message: "Cow deleted successfully" });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};
