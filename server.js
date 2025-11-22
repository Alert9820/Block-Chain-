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

// Secret Key
const JWT_SECRET = "SUPER_SECRET_KEY";

// ---------- DB CONNECT ----------
console.log("⏳ Connecting to MongoDB...");
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");

// ---------- GRIDFS ----------
let bucket = null;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📦 GridFS Ready");
});

// ---------- HELPERS ----------
const generateHash = data => crypto.createHash("sha256").update(data).digest("hex");
const storage = multer.memoryStorage();
const upload = multer({ storage });

// ---------- MODELS ----------
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

const PublicBlock = mongoose.model("publicBlocks", BlockSchema);
const MasterBlock = mongoose.model("masterBlocks", BlockSchema);

const Meta = mongoose.model("metaRecords", new mongoose.Schema({
  key: String,
  value: String
}));

const User = mongoose.model(
  "users",
  new mongoose.Schema({
    username: String,
    password: String,
    role: String
  })
);

const RestoreRequest = mongoose.model(
  "restoreRequests",
  new mongoose.Schema({
    user: String,
    blockIndex: Number,
    reason: String,
    status: { type: String, default: "pending" },
    timestamp: String
  })
);

// ---------- Create Default Users (first time only) ----------
(async () => {
  if (await User.countDocuments() === 0) {
    await User.create({ username: "admin", password: "admin123", role: "admin" });
    await User.create({ username: "staff", password: "staff123", role: "staff" });
    console.log("👤 Default Accounts => admin/admin123 | staff/staff123");
  }
})();

// ---------- AUTH MIDDLEWARE ----------
function auth(role) {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(403).json({ error: "Not Authorized" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.status(401).json({ error: "Access Denied" });

      req.user = decoded;
      next();
    } catch {
      return res.status(403).json({ error: "Invalid Token" });
    }
  };
}

// ---------- LOGIN ----------
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const u = await User.findOne({ username });

  if (!u) return res.json({ error: "User not found" });
  if (password !== u.password) return res.json({ error: "Incorrect password" });

  const token = jwt.sign({ username: u.username, role: u.role }, JWT_SECRET);
  res.json({ token, role: u.role });
});

// ---------- GET LATEST BLOCK ----------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

// ---------- ADD BLOCK ----------
app.post("/addBlock", upload.single("image"), async (req, res) => {
  try {
    let imageHash = "";
    let imageId = "";

    if (req.file) {
      if (!bucket) return res.status(500).json({ error: "Storage initializing, try again." });

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

    const newBlock = { index, timestamp, text: req.body.text, imageHash, imageId, previousHash, hash };

    await PublicBlock.create(newBlock);
    await MasterBlock.create(newBlock);

    await Meta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

    res.json({ success: true, block: newBlock });

  } catch (e) {
    res.status(500).json({ error: "Add block failed" });
  }
});

// ---------- FETCH CHAIN ----------
app.get("/chain", async (_, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// ---------- FREEZE / INVALIDATE (Admin Only) ----------
app.post("/freeze/:i", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.i }, { status: "frozen" });
  res.json({ ok: true });
});

app.post("/invalidate/:i", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.i }, { status: "invalid" });
  res.json({ ok: true });
});

// ---------- VALIDATE CHAIN ----------
app.get("/validate", async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const meta = await Meta.findOne({ key: "lastHash" });

  for (let i = 0; i < chain.length; i++)
    if (chain[i].index !== i + 1) return res.json({ valid: false, reason: `Block ${i + 1} Missing` });

  for (let i = 1; i < chain.length; i++)
    if (chain[i].previousHash !== chain[i - 1].hash)
      return res.json({ valid: false, reason: `Tampered at block ${i}` });

  if (meta && chain.length && meta.value !== chain[chain.length - 1].hash)
    return res.json({ valid: false, reason: "Last block removed" });

  res.json({ valid: true });
});

// ---------- STAFF: REQUEST RESTORE ----------
app.post("/restore/request", auth("staff"), async (req, res) => {
  const { blockIndex, reason } = req.body;

  await RestoreRequest.create({
    user: req.user.username,
    blockIndex,
    reason,
    timestamp: new Date().toISOString()
  });

  res.json({ success: true, message: "Request submitted" });
});

// ---------- ADMIN: SEE REQUESTS ----------
app.get("/restore/requests", auth("admin"), async (_, res) => {
  res.json(await RestoreRequest.find());
});

// ---------- ADMIN APPROVE ----------
app.post("/restore/approve/:id", auth("admin"), async (req, res) => {
  const rq = await RestoreRequest.findById(req.params.id);
  if (!rq) return res.json({ error: "Request not found" });

  const masterData = await MasterBlock.find().sort({ index: 1 });
  await PublicBlock.deleteMany({});
  for (let b of masterData) await PublicBlock.create(JSON.parse(JSON.stringify(b)));

  rq.status = "approved";
  await rq.save();

  res.json({ restored: true });
});

// ---------- ADMIN REJECT ----------
app.post("/restore/reject/:id", auth("admin"), async (req, res) => {
  await RestoreRequest.findByIdAndUpdate(req.params.id, { status: "rejected" });
  res.json({ rejected: true });
});

// ---------- FETCH FILE ----------
app.get("/file/:id", (req, res) => {
  try {
    const stream = bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id));
    stream.on("error", () => res.status(404).send("File missing"));
    stream.pipe(res);
  } catch {
    res.status(404).send("Invalid ID");
  }
});

// ---------- SERVER START ----------
app.listen(10000, () => console.log("🚀 Server Live @ Port 10000"));
