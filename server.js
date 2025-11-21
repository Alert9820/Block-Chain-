import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import crypto from "crypto";
import { GridFSBucket } from "mongodb";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

// -------------------------------
// DB CONNECT
// -------------------------------
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("DB Error:", err));

const conn = mongoose.connection;

// -------------------------------
// GRIDFS BUCKET
// -------------------------------
let bucket;

conn.once("open", () => {
  bucket = new GridFSBucket(conn.db, { bucketName: "evidenceFiles" });
  console.log("GridFSBucket Ready");
});

// -------------------------------
// HASH FUNCTION
// -------------------------------
function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// -------------------------------
// MULTER MEMORY STORAGE
// -------------------------------
const storage = multer.memoryStorage();
const upload = multer({ storage });

// -------------------------------
// MONGO MODELS
// -------------------------------
const BlockSchema = new mongoose.Schema({
  index: Number,
  timestamp: String,
  text: String,
  imageHash: String,
  imageId: String,
  previousHash: String,
  hash: String,
  status: { type: String, default: "valid" }
});
const Block = mongoose.model("Block", BlockSchema);

const MetaSchema = new mongoose.Schema({
  key: String,
  value: String
});
const Meta = mongoose.model("Meta", MetaSchema);

// -------------------------------
// GET LATEST BLOCK
// -------------------------------
async function getLatest() {
  return await Block.findOne().sort({ index: -1 });
}

// -------------------------------
// ADD BLOCK
// -------------------------------
app.post("/addBlock", upload.single("image"), async (req, res) => {
  try {
    const { text } = req.body;

    let imageHash = "";
    let imageId = "";

    if (req.file) {
      imageHash = generateHash(req.file.buffer);

      const uploadStream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
      uploadStream.end(req.file.buffer);

      imageId = uploadStream.id.toString();
    }

    const latest = await getLatest();
    const index = latest ? latest.index + 1 : 1;
    const previousHash = latest ? latest.hash : "0";
    const timestamp = new Date().toISOString();

    const combined = text + imageHash + timestamp + previousHash;
    const hash = generateHash(combined);

    const block = await Block.create({
      index,
      timestamp,
      text,
      imageHash,
      imageId,
      previousHash,
      hash,
      status: "valid"
    });

    await Meta.findOneAndUpdate(
      { key: "lastHash" },
      { value: hash },
      { upsert: true }
    );

    res.json(block);

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error adding block" });
  }
});

// -------------------------------
// FREEZE BLOCK
// -------------------------------
app.post("/freeze/:index", async (req, res) => {
  const block = await Block.findOne({ index: req.params.index });
  if (!block) return res.json({ error: "Block not found" });

  block.status = "frozen";
  await block.save();
  res.json(block);
});

// -------------------------------
// INVALIDATE BLOCK
// -------------------------------
app.post("/invalidate/:index", async (req, res) => {
  const block = await Block.findOne({ index: req.params.index });
  if (!block) return res.json({ error: "Block not found" });

  block.status = "invalid";
  await block.save();
  res.json(block);
});

// -------------------------------
// FULL CHAIN
// -------------------------------
app.get("/chain", async (req, res) => {
  const chain = await Block.find().sort({ index: 1 });
  res.json(chain);
});

// -------------------------------
// VALIDATE + DELETE DETECTION
// -------------------------------
app.get("/validate", async (req, res) => {
  const chain = await Block.find().sort({ index: 1 });
  const lastMeta = await Meta.findOne({ key: "lastHash" });

  // Missing block detection
  for (let i = 0; i < chain.length; i++) {
    if (chain[i].index !== i + 1) {
      return res.json({
        valid: false,
        reason: "Block deleted",
        missingIndex: i + 1
      });
    }
  }

  // Chain tamper check
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].previousHash !== chain[i - 1].hash) {
      return res.json({
        valid: false,
        reason: "Hash mismatch",
        tamperedAt: chain[i].index
      });
    }
  }

  // Last hash mismatch = deletion of last block
  if (chain.length && lastMeta && lastMeta.value !== chain[chain.length - 1].hash) {
    return res.json({
      valid: false,
      reason: "Last block removed"
    });
  }

  res.json({ valid: true });
});

// -------------------------------
// GET IMAGE FILE BY ID
// -------------------------------
app.get("/file/:id", async (req, res) => {
  try {
    const id = new mongoose.Types.ObjectId(req.params.id);
    const stream = bucket.openDownloadStream(id);
    stream.pipe(res);
  } catch (e) {
    res.status(404).send("File not found");
  }
});

// -------------------------------
// SERVER START
// -------------------------------
app.listen(10000, () => console.log("Server running on port 10000"));
