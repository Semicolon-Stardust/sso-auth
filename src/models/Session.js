// src/models/Session.js
import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, refPath: 'userModel', required: true },
    userModel: { type: String, required: true, enum: ['User', 'Admin'] },
    token: { type: String, required: true },
    ipAddress: { type: String, required: true },
    location: { type: String, default: 'Unknown' },
    userAgent: { type: String, default: 'Unknown' },
  },
  { timestamps: true }
);

export default mongoose.model('Session', sessionSchema);
