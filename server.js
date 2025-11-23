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

const JWT_SECRET = "SUPER_SECRET_KEY";

// Serve login first
app.use(express.static("public"));
app.get("/", (req, res) => res.sendFile(process.cwd() + "/public/login.html"));

// DB CONNECT
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");

// GRIDFS INIT
let bucket = null;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📦 File Storage Ready");
});

// Helpers
const hashGen = d => crypto.createHash("sha256").update(d).digest("hex");
const upload = multer({ storage: multer.memoryStorage() });

// Models
const BlockSchema = {
  index: Number, timestamp: String, text: String,
  imageHash: String, imageId: String, previousHash: String,
  hash: String, status: { type: String, default: "valid" }
};
const PublicBlock = mongoose.model("publicBlocks", BlockSchema);
const MasterBlock = mongoose.model("masterBlocks", BlockSchema);
const Meta = mongoose.model("metaRecords", { key: String, value: String });

const User = mongoose.model("UX", {
  username: String, password: String, role: String
});

const RestoreRequest = mongoose.model("restoreRequests", {
  user: String, blockIndex: Number, reason: String,
  status: { type: String, default: "pending" }, timestamp: String
});

// Create default accounts once
if (await User.countDocuments() === 0) {
  await User.create({ username: "admin", password: "admin123", role: "admin" });
  await User.create({ username: "staff", password: "staff123", role: "staff" });
  console.log("👤 Accounts Ready: admin/admin123 | staff/staff123");
}

// Middleware
function auth(role) {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.json({ error: "No token" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.json({ error: "Access Denied" });
      req.user = decoded;
      next();
    } catch { return res.json({ error: "Invalid Token" }); }
  };
}

// Login
app.post("/auth/login", async (req, res) => {
  const u = await User.findOne({ username: req.body.username });
  if (!u) return res.json({ error: "User not found" });
  if (u.password !== req.body.password) return res.json({ error: "Wrong password" });

  const token = jwt.sign({ username: u.username, role: u.role }, JWT_SECRET);
  res.json({ token, role: u.role });
});

// Get latest block
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

// Add Block
app.post("/addBlock", auth("staff"), upload.single("image"), async (req, res) => {
  let imgHash = "", imgId = "";

  if (req.file) {
    if (!bucket) return res.json({ error: "Wait, storage loading..." });

    imgHash = hashGen(req.file.buffer);
    const stream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
    stream.end(req.file.buffer);
    imgId = stream.id.toString();
  }

  const prev = await getLatest();
  const index = prev ? prev.index + 1 : 1;
  const timestamp = new Date().toISOString();
  const prevHash = prev ? prev.hash : "0";
  const hash = hashGen(req.body.text + imgHash + timestamp + prevHash);

  const block = { index, timestamp, text: req.body.text, imageHash: imgHash, imageId: imgId, previousHash: prevHash, hash };

  await PublicBlock.create(block);
  await MasterBlock.create(block);
  await Meta.findOneAndUpdate({ key:"lastHash" },{value:hash},{upsert:true});

  res.json({ success: true, block });
});

// Staff view
app.get("/chain/staff", auth("staff"), async (_, res) => {
  let chain = await PublicBlock.find().sort({ index: 1 });
  chain = chain.map(b => ({ ...b._doc, imageHash: undefined, hash: undefined, previousHash: undefined }));
  res.json(chain);
});

// Admin view
app.get("/chain/admin", auth("admin"), async (_, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// Reveal Image (ADMIN only)
app.get("/reveal/:id", auth("admin"), async (req, res) => {
  try {
    bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id)).pipe(res);
  } catch {
    res.send("Image missing");
  }
});

// Freeze & Invalidate
app.post("/freeze/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "frozen" });
  res.json({ ok: true });
});

app.post("/invalidate/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "invalid" });
  res.json({ ok: true });
});

// Restore System
app.post("/restore/request", auth("staff"), async (req, res) => {
  await RestoreRequest.create({
    user: req.user.username, blockIndex: req.body.blockIndex,
    reason: req.body.reason, timestamp: new Date().toISOString()
  });
  res.json({ sent: true });
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

// Start server
app.listen(10000, () => console.log("🚀 Running @10000"));
