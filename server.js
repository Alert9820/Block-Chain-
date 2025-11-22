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

// ---------------------- STATIC + LOGIN REDIRECT ----------------------
app.get("/", (req, res) => {
  res.sendFile(process.cwd() + "/public/login.html");
});
app.use(express.static("public"));

// ---------------------- JWT SECRET ----------------------
const JWT_SECRET = "SUPER_SECRET_KEY";

// ---------------------- DATABASE ----------------------
console.log("⏳ Connecting to MongoDB...");
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");

// ---------------------- GRIDFS ----------------------
let bucket = null;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📦 GridFS Ready");
});

// ---------------------- MULTER ----------------------
const upload = multer({ storage: multer.memoryStorage() });

// ---------------------- MODELS ----------------------
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

// ⭐ USERS collection name = "UX"
const User = mongoose.model(
  "UX", 
  new mongoose.Schema({
    username: String,
    password: String,
    role: String
  }),
  "UX"
);

const RestoreRequest = mongoose.model("restoreRequests", {
  user: String,
  blockIndex: Number,
  reason: String,
  status: { type: String, default: "pending" },
  timestamp: String
});

// ---------------------- DEFAULT USERS (RUN AFTER DB READY) ----------------------
mongoose.connection.once("open", async () => {
  const count = await User.countDocuments();
  if (count === 0) {
    await User.insertMany([
      { username: "admin", password: "admin123", role: "admin" },
      { username: "staff", password: "staff123", role: "staff" }
    ]);

    console.log("👤 Default UX users created:");
    console.log("➡ admin/admin123");
    console.log("➡ staff/staff123");
  } else {
    console.log("✔ UX users already exist — skipping creation.");
  }
});

// ---------------------- AUTH MIDDLEWARE ----------------------
function auth(role) {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.json({ error: "Token missing" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.json({ error: "Permission denied" });

      req.user = decoded;
      next();
    } catch {
      res.json({ error: "Invalid token" });
    }
  };
}

// ---------------------- LOGIN ROUTE ----------------------
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });

  if (!user) return res.json({ error: "User not found" });
  if (user.password !== password) return res.json({ error: "Wrong password" });

  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET);
  res.json({ token, role: user.role });
});

// ---------------------- BLOCKCHAIN FUNCTIONS ----------------------
const generateHash = text => crypto.createHash("sha256").update(text).digest("hex");

async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

app.post("/addBlock", upload.single("image"), async (req, res) => {
  try {
    let imageHash = "";
    let imageId = "";

    if (req.file) {
      if (!bucket) return res.json({ error: "Storage initializing, try again." });

      imageHash = generateHash(req.file.buffer);
      const stream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
      stream.end(req.file.buffer);
      imageId = stream.id.toString();
    }

    const latest = await getLatest();
    const index = latest ? latest.index + 1 : 1;
    const timestamp = new Date().toISOString();
    const previousHash = latest ? latest.hash : "0";
    const hash = generateHash(req.body.text + imageHash + timestamp + previousHash);

    const block = { index, timestamp, text: req.body.text, imageHash, imageId, previousHash, hash };

    await PublicBlock.create(block);
    await MasterBlock.create(block);
    await Meta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

    res.json({ success: true, block });

  } catch (err) {
    res.json({ error: "Block creation failed" });
  }
});

app.get("/chain", async (_, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// ---------------------- ADMIN ACTIONS ----------------------
app.post("/freeze/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "frozen" });
  res.json({ done: true });
});

app.post("/invalidate/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "invalid" });
  res.json({ done: true });
});

// ---------------------- VALIDATE CHAIN ----------------------
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

// ---------------------- RESTORE REQUEST SYSTEM ----------------------
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
  const request = await RestoreRequest.findById(req.params.id);

  const full = await MasterBlock.find().sort({ index: 1 });
  await PublicBlock.deleteMany({});
  for (let b of full) await PublicBlock.create(JSON.parse(JSON.stringify(b)));

  request.status = "approved";
  await request.save();

  res.json({ restored: true });
});

app.post("/restore/reject/:id", auth("admin"), async (req, res) => {
  await RestoreRequest.findByIdAndUpdate(req.params.id, { status: "rejected" });
  res.json({ rejected: true });
});

// ---------------------- FILE FETCH ----------------------
app.get("/file/:id", (req, res) => {
  try {
    bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id)).pipe(res);
  } catch {
    res.status(404).send("File missing");
  }
});

// ---------------------- START SERVER ----------------------
app.listen(10000, () => console.log("🚀 Server Live on 10000"));
