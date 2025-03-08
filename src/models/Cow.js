// src/models/Cow.js
import mongoose from "mongoose";

const CowSchema = new mongoose.Schema(
	{
		name: { type: String, required: true },
		photo: { type: String },
		age: { type: Number, required: true },
		sicknessStatus: { type: Boolean, default: false },
		agedStatus: { type: Boolean, default: false },
		adoptionStatus: { type: Boolean, default: false },
	},
	{ timestamps: true }
);

export default mongoose.model("Cow", CowSchema);
