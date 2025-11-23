import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { GridFSBucket } from "mongodb";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// Serve login FIRST
app.get("/", (req, res) => {
  res.sendFile(process.cwd() + "/public/login.html");
});

app.use(express.static("public"));

const JWT_SECRET = "SUPER_SECRET_KEY";

// ---------------------- DB CONNECT ----------------------
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");

// ---------------------- GRIDFS ----------------------
let bucket;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📦 GridFS Ready");
});

// ---------------------- HELPERS ----------------------
const upload = multer({ storage: multer.memoryStorage() });
const hashGen = buffer => crypto.createHash("sha256").update(buffer).digest("hex");

// ---------------------- SCHEMAS ----------------------
const BlockSchema = {
  index: Number,
  timestamp: String,
  text: String,
  imageId: String,
  imageHash: String,
  previousHash: String,
  hash: String,
  status: { type: String, default: "valid" }
};

const PublicBlock = mongoose.model("publicBlocks", BlockSchema);
const MasterBlock = mongoose.model("masterBlocks", BlockSchema);
const Meta = mongoose.model("metaRecords", { key: String, value: String });

// Users stored in `UX` collection (requested by you)
const User = mongoose.model("UX", new mongoose.Schema({
  username: String,
  password: String,
  role: String
}), "UX");

const RestoreRequest = mongoose.model("restoreRequests", {
  user: String,
  blockIndex: Number,
  reason: String,
  status: { type: String, default: "pending" },
  timestamp: String
});

// ---------------------- DEFAULT USERS ----------------------
mongoose.connection.once("open", async () => {
  if (await User.countDocuments() === 0) {
    await User.insertMany([
      { username: "admin", password: "admin123", role: "admin" },
      { username: "staff", password: "staff123", role: "staff" }
    ]);

    console.log("👤 Default users created.");
  }
});

// ---------------------- AUTH ----------------------
function auth(role) {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.json({ error: "Login Required" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.json({ error: "Access Denied" });

      req.user = decoded;
      next();
    } catch {
      res.json({ error: "Invalid Token" });
    }
  };
}

// ---------------------- LOGIN ROUTE ----------------------
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const u = await User.findOne({ username });

  if (!u) return res.json({ error: "User not found" });
  if (u.password !== password) return res.json({ error: "Wrong password" });

  const token = jwt.sign({ username: u.username, role: u.role }, JWT_SECRET);
  res.json({ token, role: u.role });
});

// ---------------------- ADD BLOCK ----------------------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

app.post("/addBlock", auth(), upload.single("image"), async (req, res) => {
  let imageHash = "";
  let imageId = "";

  if (req.file) {
    const stream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
    stream.end(req.file.buffer);
    imageHash = hashGen(req.file.buffer);
    imageId = stream.id.toString();
  }

  const prev = await getLatest();
  const index = prev ? prev.index + 1 : 1;
  const timestamp = new Date().toISOString();
  const previousHash = prev ? prev.hash : "0";
  const hash = hashGen((req.body.text || "") + imageHash + timestamp + previousHash);

  const block = { index, timestamp, text: req.body.text, imageId, imageHash, previousHash, hash };
  await PublicBlock.create(block);
  await MasterBlock.create(block);

  await Meta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

  res.json({ success: true });
});

// ---------------------- VIEW CHAIN ----------------------
app.get("/chain", auth(), async (_, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// ---------------------- SECURE IMAGE REVEAL ----------------------
app.get("/admin/reveal/:id", auth("admin"), async (req, res) => {
  try {
    const block = await PublicBlock.findOne({ imageId: req.params.id });
    let chunks = [];

    const stream = bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id));
    
    stream.on("data", chunk => chunks.push(chunk));
    stream.on("end", () => {
      const data = Buffer.concat(chunks);
      const newHash = hashGen(data);

      if (newHash !== block.imageHash)
        return res.json({ error: "❌ Evidence Tampered (Hash Mismatch)" });

      res.set({ "Content-Type": "image/jpeg" });
      res.end(data);
    });

  } catch {
    res.json({ error: "File Missing" });
  }
});

// ---------------------- ADMIN CONTROLS ----------------------
app.post("/freeze/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "frozen" });
  res.json({ done: true });
});

app.post("/invalidate/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "invalid" });
  res.json({ done: true });
});

// ---------------------- VALIDATE BLOCKCHAIN ----------------------
app.get("/validate", auth(), async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const last = await Meta.findOne({ key: "lastHash" });

  for (let i = 1; i < chain.length; i++)
    if (chain[i].previousHash !== chain[i - 1].hash)
      return res.json({ valid: false });

  if (last.value !== chain[chain.length - 1].hash)
    return res.json({ valid: false });

  res.json({ valid: true });
});

// ---------------------- RESTORE SYSTEM ----------------------
app.post("/restore/request", auth("staff"), async (req, res) => {
  await RestoreRequest.create({
    user: req.user.username,
    blockIndex: req.body.blockIndex,
    reason: req.body.reason,
    timestamp: new Date().toISOString()
  });

  res.json({ requested: true });
});

app.get("/restore/requests", auth("admin"), async (_, res) => {
  res.json(await RestoreRequest.find());
});

app.post("/restore/approve/:id", auth("admin"), async (req, res) => {
  const full = await MasterBlock.find().sort({ index: 1 });
  await PublicBlock.deleteMany({});
  for (let b of full) await PublicBlock.create(JSON.parse(JSON.stringify(b)));

  await RestoreRequest.findByIdAndUpdate(req.params.id, { status: "approved" });
  res.json({ restored: true });
});

app.post("/restore/reject/:id", auth("admin"), async (req, res) => {
  await RestoreRequest.findByIdAndUpdate(req.params.id, { status: "rejected" });
  res.json({ rejected: true });
});

// ---------------------- START SERVER ----------------------
app.listen(10000, () => console.log("🚀 System Running @ PORT 10000"));
