// src/models/Donation.js
import mongoose from "mongoose";

const DonationSchema = new mongoose.Schema(
	{
		user: { type: String, required: true },
		amount: { type: Number, required: true },
		tier: {
			type: String,
			enum: ["Bronze", "Silver", "Gold"],
			required: true,
		},
		donationType: {
			type: String,
			enum: ["one-time", "recurring"],
			required: true,
		},
		recurringFrequency: {
			type: String,
			enum: ["monthly", "quarterly", "yearly"],
		},
		transactionDetails: { type: Object },
	},
	{ timestamps: true }
);

export default mongoose.model("Donation", DonationSchema);
