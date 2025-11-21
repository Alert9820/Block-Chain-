import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import { GridFsStorage } from "multer-gridfs-storage";
import Grid from "gridfs-stream";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

// --------------------------
// DB CONNECT
// --------------------------
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

// GRIDFS INIT
let gfs;
const conn = mongoose.connection;

conn.once("open", () => {
  gfs = Grid(conn.db, mongoose.mongo);
  gfs.collection("evidenceFiles");
  console.log("GridFS Ready");
});

// --------------------------
// HASH FUNCTION
// --------------------------
function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// --------------------------
// MULTER GRIDFS STORAGE (REAL IMAGE STORAGE)
// --------------------------
const storage = new GridFsStorage({
  url: process.env.MONGO_URL,
  file: (req, file) => ({
    bucketName: "evidenceFiles",
    filename: Date.now() + "-" + file.originalname
  })
});
const upload = multer({ storage });

// --------------------------
// BLOCKCHAIN IN MONGODB
// --------------------------
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

// META store lastHash to detect deletion
const MetaSchema = new mongoose.Schema({
  key: String,
  value: String
});
const Meta = mongoose.model("Meta", MetaSchema);

// --------------------------
// UTILITY: GET LAST BLOCK
// --------------------------
async function getLatest() {
  return await Block.findOne().sort({ index: -1 });
}

// --------------------------
// ADD BLOCK
// --------------------------
app.post("/addBlock", upload.single("image"), async (req, res) => {
  try {
    const { text } = req.body;

    let imageHash = "";
    let imageId = "";

    if (req.file) {
      imageHash = generateHash(req.file.buffer);
      imageId = req.file.id;
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

// --------------------------
// FREEZE BLOCK
// --------------------------
app.post("/freeze/:index", async (req, res) => {
  const block = await Block.findOne({ index: req.params.index });
  if (!block) return res.json({ error: "Not found" });
  block.status = "frozen";
  await block.save();
  res.json(block);
});

// --------------------------
// INVALIDATE BLOCK
// --------------------------
app.post("/invalidate/:index", async (req, res) => {
  const block = await Block.findOne({ index: req.params.index });
  if (!block) return res.json({ error: "Not found" });
  block.status = "invalid";
  await block.save();
  res.json(block);
});

// --------------------------
// GET FULL CHAIN
// --------------------------
app.get("/chain", async (req, res) => {
  res.json(await Block.find().sort({ index: 1 }));
});

// --------------------------
// VALIDATE CHAIN (DELETION + TAMPER + LAST HASH)
// --------------------------
app.get("/validate", async (req, res) => {
  const chain = await Block.find().sort({ index: 1 });
  const lastMeta = await Meta.findOne({ key: "lastHash" });

  // Check for missing indexes
  for (let i = 0; i < chain.length; i++) {
    if (chain[i].index !== i + 1) {
      return res.json({
        valid: false,
        missingIndex: i + 1,
        reason: "Block deleted"
      });
    }
  }

  // Check hash linking
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].previousHash !== chain[i - 1].hash) {
      return res.json({
        valid: false,
        reason: "Chain tampered",
        tamperedAt: chain[i].index
      });
    }
  }

  // Check final hash match
  if (chain.length && lastMeta && lastMeta.value !== chain[chain.length - 1].hash) {
    return res.json({
      valid: false,
      reason: "Last block removed"
    });
  }

  res.json({ valid: true });
});

// --------------------------
// FETCH IMAGE FILE
// --------------------------
app.get("/file/:id", async (req, res) => {
  try {
    const id = new mongoose.Types.ObjectId(req.params.id);

    gfs.files.findOne({ _id: id }, (err, file) => {
      if (!file) return res.status(404).send("File not found");

      const readStream = gfs.createReadStream({ _id: id });
      readStream.pipe(res);
    });
  } catch {
    res.status(500).send("Invalid ID");
  }
});

// --------------------------
app.listen(10000, () => console.log("Server running at 10000"));
