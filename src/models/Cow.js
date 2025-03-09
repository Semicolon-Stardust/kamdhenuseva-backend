import mongoose from "mongoose";

const CowSchema = new mongoose.Schema(
	{
		name: { type: String, required: true },
		photo: { type: String },
		description: { type: String }, // New field added instead of age
		sicknessStatus: { type: Boolean, default: false },
		gender: { type: String},
		agedStatus: { type: Boolean, default: false },
		adoptionStatus: { type: Boolean, default: false },
	},
	{ timestamps: true }
);

export default mongoose.model("Cow", CowSchema);
