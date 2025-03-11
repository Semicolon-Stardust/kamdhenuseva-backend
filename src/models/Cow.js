import mongoose from "mongoose";

const CowSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    photos: { type: [String], default: [] },
    description: { type: String },
    sicknessStatus: { type: Boolean, default: false },
    gender: { type: String },
    agedStatus: { type: Boolean, default: false },
    adoptionStatus: { type: Boolean, default: false },
  },
  { timestamps: true }
);

export default mongoose.model("Cow", CowSchema);
