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
app.use(express.static("public"));

const JWT_SECRET = "SUPER_SECRET_KEY";

// 🟢 DEFAULT ROUTE → LOGIN PAGE
// Serve login page first ALWAYS
app.get("/", (req, res) => {
  res.sendFile(process.cwd() + "/public/login.html");
});

// After defining root route THEN serve static folder
app.use(express.static("public"));

// ------------------ DB CONNECT ------------------
console.log("⏳ Connecting to MongoDB...");
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");

// ---------------- GRID FS ----------------
let bucket = null;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📦 GridFS Ready");
});

// ---------------- HELPERS ----------------
const generateHash = text => crypto.createHash("sha256").update(text).digest("hex");
const upload = multer({ storage: multer.memoryStorage() });

// ---------------- SCHEMAS ----------------
const BlockSchema = {
  index: Number,
  timestamp: String,
  text: String,
  imageHash: String,
  imageId: String,
  previousHash: String,
  hash: String,
  status: { type: String, default: "valid" }
};

const PublicBlock = mongoose.model("publicBlocks", BlockSchema);
const MasterBlock = mongoose.model("masterBlocks", BlockSchema);

const Meta = mongoose.model("metaRecords", { key: String, value: String });

const User = mongoose.model("users", {
  username: String,
  password: String,
  role: String
});

const RestoreRequest = mongoose.model("restoreRequests", {
  user: String,
  blockIndex: Number,
  reason: String,
  status: { type: String, default: "pending" },
  timestamp: String
});

// ---------------- DEFAULT USERS ----------------
(async () => {
  if (await User.countDocuments() === 0) {
    await User.create({ username: "admin", password: "admin123", role: "admin" });
    await User.create({ username: "staff", password: "staff123", role: "staff" });
    console.log("👤 Default Accounts Ready → (admin/admin123 & staff/staff123)");
  }
})();

// ---------------- AUTH MIDDLEWARE ----------------
function auth(role) {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(403).json({ error: "Token Missing" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.json({ error: "Permission Denied" });

      req.user = decoded;
      next();
    } catch {
      return res.status(403).json({ error: "Invalid Token" });
    }
  };
}

// ---------------- LOGIN ----------------
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const u = await User.findOne({ username });

  if (!u) return res.json({ error: "User not found" });
  if (password !== u.password) return res.json({ error: "Wrong password" });

  const token = jwt.sign({ username, role: u.role }, JWT_SECRET);
  res.json({ token, role: u.role });
});

// ---------------- GET LATEST BLOCK ----------------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

// ---------------- ADD BLOCK ----------------
app.post("/addBlock", upload.single("image"), async (req, res) => {
  try {
    let imageHash = "";
    let imageId = "";

    if (req.file) {
      if (!bucket) return res.json({ error: "Storage not ready, retry." });

      imageHash = generateHash(req.file.buffer);
      const stream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
      stream.end(req.file.buffer);
      imageId = stream.id.toString();
    }

    const prev = await getLatest();
    const index = prev ? prev.index + 1 : 1;
    const timestamp = new Date().toISOString();
    const previousHash = prev ? prev.hash : "0";
    const hash = generateHash(req.body.text + imageHash + timestamp + previousHash);

    const block = { index, timestamp, text: req.body.text, imageHash, imageId, previousHash, hash };

    await PublicBlock.create(block);
    await MasterBlock.create(block);
    await Meta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

    res.json({ success: true, block });

  } catch {
    res.json({ error: "Block creation failed" });
  }
});

// ---------------- DISPLAY CHAIN ----------------
app.get("/chain", async (_, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// ---------------- ADMIN CONTROLS ----------------
app.post("/freeze/:i", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.i }, { status: "frozen" });
  res.json({ ok: true });
});

app.post("/invalidate/:i", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.i }, { status: "invalid" });
  res.json({ ok: true });
});

// ---------------- VALIDATION ----------------
app.get("/validate", async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const meta = await Meta.findOne({ key: "lastHash" });

  for (let i = 0; i < chain.length; i++)
    if (chain[i].index !== i + 1) return res.json({ valid: false, issue: `Block missing: ${i + 1}` });

  for (let i = 1; i < chain.length; i++)
    if (chain[i].previousHash !== chain[i - 1].hash)
      return res.json({ valid: false, issue: `Tampered at block ${i}` });

  if (meta && chain.length && meta.value !== chain[chain.length - 1].hash)
    return res.json({ valid: false, issue: "Last block deleted" });

  res.json({ valid: true });
});

// ---------------- RESTORE REQUESTS ----------------
app.post("/restore/request", auth("staff"), async (req, res) => {
  await RestoreRequest.create({
    user: req.user.username,
    blockIndex: req.body.blockIndex,
    reason: req.body.reason,
    timestamp: new Date().toISOString()
  });

  res.json({ message: "Request submitted" });
});

app.get("/restore/requests", auth("admin"), async (_, res) => {
  res.json(await RestoreRequest.find());
});

app.post("/restore/approve/:id", auth("admin"), async (req, res) => {
  const r = await RestoreRequest.findById(req.params.id);

  const full = await MasterBlock.find().sort({ index: 1 });
  await PublicBlock.deleteMany({});
  for (let b of full) await PublicBlock.create(JSON.parse(JSON.stringify(b)));

  r.status = "approved";
  await r.save();

  res.json({ restored: true });
});

app.post("/restore/reject/:id", auth("admin"), async (req, res) => {
  await RestoreRequest.findByIdAndUpdate(req.params.id, { status: "rejected" });
  res.json({ rejected: true });
});

// ---------------- FETCH FILE ----------------
app.get("/file/:id", (req, res) => {
  try {
    bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id)).pipe(res);
  } catch {
    res.status(404).send("File Missing");
  }
});

// ---------------- SERVER ----------------
app.listen(10000, () => console.log("🚀 Running on PORT 10000"));
