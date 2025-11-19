import mongoose from "mongoose";

const BlockSchema = new mongoose.Schema({
    index: Number,
    timestamp: String,
    text: String,
    imageHash: String,
    previousHash: String,
    hash: String
});

export default mongoose.model("Block", BlockSchema);
