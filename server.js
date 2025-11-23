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

// ------------------- DB CONNECT -------------------
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");

// ------------------- GRIDFS ------------------------
let bucket = null;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "files" });
  console.log("📦 Storage Ready");
});

// ------------------- HELPERS -----------------------
const hashGen = buffer => crypto.createHash("sha256").update(buffer).digest("hex");
const upload = multer({ storage: multer.memoryStorage() });

// ------------------- DB MODELS ---------------------
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

const Meta = mongoose.model("metaTable", { key: String, value: String });

const User = mongoose.model("UX", {
  username: String,
  password: String,
  role: String
});

const Activity = mongoose.model("activityLogs", {
  user: String,
  message: String,
  time: String
});

const RestoreRequest = mongoose.model("restoreRequests", {
  user: String,
  blockIndex: Number,
  reason: String,
  status: { type: String, default: "pending" },
  time: String
});

// -------- Default Users (first time only) ----------
if (await User.countDocuments() === 0) {
  await User.create({ username: "admin", password: "admin123", role: "admin" });
  await User.create({ username: "staff", password: "staff123", role: "staff" });
  console.log("👤 Accounts Ready: admin/admin123 | staff/staff123");
}

// ------------------- MIDDLEWARE --------------------
function auth(role = null) {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.json({ error: "Access Denied: Login First" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.json({ error: "Forbidden" });
      req.user = decoded;
      next();
    } catch {
      res.json({ error: "Session Expired" });
    }
  };
}

// ------------------- LOGIN -------------------------
app.post("/auth/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username });

  if (!user) return res.json({ error: "Username incorrect" });
  if (user.password !== req.body.password) return res.json({ error: "Wrong password" });

  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET);

  await Activity.create({ user: user.username, message: "Logged in", time: new Date().toISOString() });

  res.json({ token, role: user.role });
});

// ------------------- LOGOUT LOG --------------------
app.post("/activity/logout", auth(), async (req, res) => {
  await Activity.create({ user: req.user.username, message: "Logged out", time: new Date().toISOString() });
  res.json({ done: true });
});

// ------------------- BLOCKCHAIN FUNCTIONS ----------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

// ADD EVIDENCE
app.post("/addBlock", auth("staff"), upload.single("image"), async (req, res) => {
  let imgHash = "", imgId = "";

  if (req.file) {
    if (!bucket) return res.json({ error: "Storage starting... retry" });

    imgHash = hashGen(req.file.buffer);
    const stream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
    stream.end(req.file.buffer);
    imgId = stream.id.toString();
  }

  const prev = await getLatest();
  const index = prev ? prev.index + 1 : 1;
  const timestamp = new Date().toISOString();
  const prevHash = prev ? prev.hash : "0";
  const hash = hashGen(Buffer.from(req.body.text + imgHash + timestamp + prevHash));

  const block = { index, timestamp, text: req.body.text, imageId: imgId, imageHash: imgHash, previousHash: prevHash, hash };

  await PublicBlock.create(block);
  await MasterBlock.create(block);
  await Meta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

  res.json({ success: true });
});

// STAFF VIEW
app.get("/chain/staff", auth("staff"), async (req, res) => {
  let chain = await PublicBlock.find().sort({ index: 1 });
  chain = chain.map(b => ({ index: b.index, text: b.text, status: b.status, timestamp: b.timestamp }));
  res.json(chain);
});

// ADMIN VIEW
app.get("/chain/admin", auth("admin"), async (req, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// ------------------- VALIDATION ---------------------
app.get("/validate", auth(), async (req, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const meta = await Meta.findOne({ key: "lastHash" });

  if (!chain.length) return res.json({ valid: true, msg: "📦 Blockchain Empty (Safe)" });

  for (let i = 0; i < chain.length; i++)
    if (chain[i].index !== i + 1) return res.json({ valid: false, msg: "⚠ Missing Block detected" });

  if (meta.value !== chain.at(-1).hash)
    return res.json({ valid: false, msg: "⚠ Someone tried to delete last block!" });

  res.json({ valid: true, msg: "✔ Blockchain Safe" });
});

// ------------------- IMAGE REVEAL (ADMIN ONLY) -----
app.get("/reveal/:id", auth("admin"), (req, res) => {
  try {
    bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id)).pipe(res);
  } catch {
    res.send("Image Missing");
  }
});

// ------------------- FREEZE -------------------------
app.post("/freeze/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "Frozen" });
  res.json({ done: true });
});

// ------------------- INVALIDATE ---------------------
app.post("/invalidate/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "Invalidated" });
  res.json({ done: true });
});

// ------------------- RESTORE SYSTEM -----------------
app.post("/restore/request", auth("staff"), async (req, res) => {
  await RestoreRequest.create({
    user: req.user.username,
    blockIndex: req.body.blockIndex,
    reason: req.body.reason,
    time: new Date().toISOString()
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

  r.status = "Approved";
  await r.save();

  res.json({ restored: true });
});

app.post("/restore/reject/:id", auth("admin"), async (req, res) => {
  await RestoreRequest.findByIdAndUpdate(req.params.id, { status: "Rejected" });
  res.json({ rejected: true });
});

// ------------------- LOAD ACTIVITY -------------------
app.get("/logs", auth("admin"), async (_, res) => {
  res.json(await Activity.find().sort({ _id: -1 }).limit(25));
});

// ------------------- SERVER START -------------------
app.listen(10000, () => console.log("🚀 Running @ PORT 10000"));
