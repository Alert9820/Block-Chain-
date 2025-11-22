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
// DATABASE CONNECTIONS
// -------------------------------
const publicDB = await mongoose.createConnection(process.env.MONGO_URL).asPromise();
console.log("Public DB Connected");

const masterDB = await mongoose.createConnection(process.env.MONGO_URL_MASTER).asPromise();
console.log("Master DB Connected");

// -------------------------------
// GRIDFS BUCKET (Public DB only stores files)
// -------------------------------
let bucket;

publicDB.once("open", () => {
  bucket = new GridFSBucket(publicDB.db, { bucketName: "evidenceFiles" });
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
// SCHEMAS
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

const MetaSchema = new mongoose.Schema({
  key: String,
  value: String
});

// -------------------------------
// MODELS FOR BOTH DATABASES
// -------------------------------
const PublicBlock = publicDB.model("Block", BlockSchema);
const MasterBlock = masterDB.model("Block", BlockSchema);

const PublicMeta = publicDB.model("Meta", MetaSchema);
const MasterMeta = masterDB.model("Meta", MetaSchema);

// -------------------------------
// GET LATEST PUBLIC BLOCK
// -------------------------------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
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
    const hash = generateHash(text + imageHash + timestamp + previousHash);

    const blockData = {
      index,
      timestamp,
      text,
      imageHash,
      imageId,
      previousHash,
      hash,
      status: "valid"
    };

    // Save in both DBs
    await PublicBlock.create(blockData);
    await MasterBlock.create(blockData);

    await PublicMeta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });
    await MasterMeta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

    res.json({ message: "Block added ✔", block: blockData });

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error adding block" });
  }
});

// -------------------------------
// FREEZE BLOCK
// -------------------------------
app.post("/freeze/:index", async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.index }, { status: "frozen" });
  res.json({ message: "Block frozen" });
});

// -------------------------------
// INVALIDATE BLOCK
// -------------------------------
app.post("/invalidate/:index", async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.index }, { status: "invalid" });
  res.json({ message: "Block marked invalid" });
});

// -------------------------------
// GET PUBLIC BLOCKCHAIN
// -------------------------------
app.get("/chain", async (req, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  res.json(chain);
});

// -------------------------------
// VALIDATE PUBLIC CHAIN
// -------------------------------
app.get("/validate", async (req, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const lastMeta = await PublicMeta.findOne({ key: "lastHash" });

  for (let i = 0; i < chain.length; i++) {
    if (chain[i].index !== i + 1) {
      return res.json({ valid: false, reason: "Block deleted", missingIndex: i + 1 });
    }
  }

  for (let i = 1; i < chain.length; i++) {
    if (chain[i].previousHash !== chain[i - 1].hash) {
      return res.json({ valid: false, tamperedAt: chain[i].index });
    }
  }

  if (chain.length && lastMeta && lastMeta.value !== chain[chain.length - 1].hash) {
    return res.json({ valid: false, reason: "Last block removed" });
  }

  res.json({ valid: true });
});

// -------------------------------
// SAFE IMAGE FETCH
// -------------------------------
app.get("/file/:id", async (req, res) => {
  try {
    const id = new mongoose.Types.ObjectId(req.params.id);

    const exists = await bucket.find({ _id: id }).toArray();
    if (exists.length === 0) return res.status(404).send("⚠ File Not Found");

    const stream = bucket.openDownloadStream(id);
    stream.on("error", () => res.status(404).send("⚠ Image Missing"));
    stream.pipe(res);

  } catch {
    res.status(404).send("⚠ Invalid File ID");
  }
});

// -------------------------------
// RESTORE PUBLIC DB FROM MASTER
// -------------------------------
app.post("/restore", async (req, res) => {
  await PublicBlock.deleteMany({});
  await PublicMeta.deleteMany({});

  const masterData = await MasterBlock.find().sort({ index: 1 });
  for (const block of masterData) {
    await PublicBlock.create(JSON.parse(JSON.stringify(block)));
  }

  const meta = await MasterMeta.findOne({ key: "lastHash" });
  if (meta) {
    await PublicMeta.create({ key: "lastHash", value: meta.value });
  }

  res.json({ message: "🔁 Public database restored from master ✔" });
});

// -------------------------------
// START SERVER
// -------------------------------
app.listen(10000, () => console.log("🚀 Server running on port 10000"));
