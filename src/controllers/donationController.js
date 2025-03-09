// src/controllers/donationController.js
import Donation from "../models/Donation.js";
import { sendEmail } from "../utils/helpers.js";
import User from "../models/User.js";

export const createDonation = async (req, res) => {
	try {
		// Extract user information from auth token
		const userId = req.auth.data.id;
		const donationData = {
			...req.body,
			user: userId,
		};

		// Create the donation record (integration with Razorpay can be added here)
		const donation = new Donation(donationData);
		await donation.save();

		// Send a confirmation email (if email available)
		if (req.auth.data.email) {
			try {
				await sendEmail(
					req.auth.data.email,
					"Donation Confirmation",
					"Thank you for your donation!",
					"<p>Thank you for your generous donation. We appreciate your support!</p>"
				);
			} catch (emailError) {
				console.error("Error sending confirmation email:", emailError);
			}
		}

		res.status(201).json({ data: donation });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

export const getDonationHistory = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			logger.warn("Donation: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			logger.warn(`Donation: User not found for email ${email}`);
			return sendResponse(res, 400, false, null, "User not found");
		}
		const donations = await Donation.find({ user: user }).sort({
			createdAt: -1,
		});
		res.json({ data: donations });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};

export const getAllDonations = async (req, res) => {
	try {
		const donations = await Donation.find().sort({ createdAt: -1 });
		res.json({ data: donations });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
};
