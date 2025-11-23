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

// 👉 DEFAULT PAGE (Login Page)
app.get("/", (req, res) => {
  res.sendFile(process.cwd() + "/public/login.html");
});

// 👉 Serve Frontend Files
app.use(express.static("public"));

app.get("/admin", (req, res) => {
  res.sendFile(process.cwd() + "/public/admin.html");
});

app.get("/staff", (req, res) => {
  res.sendFile(process.cwd() + "/public/staff.html");
});


// ==========================
// 🔥 Database Connection
// ==========================
console.log("⏳ Connecting to MongoDB...");
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");


// ==========================
// 📦 GridFS Init
// ==========================
let bucket = null;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📁 GridFS Bucket Ready");
});


// ==========================
// 🧠 Utilities
// ==========================
const hashGen = buffer => crypto.createHash("sha256").update(buffer).digest("hex");
const upload = multer({ storage: multer.memoryStorage() });

const JWT_SECRET = "SUPER_SECRET_SYSTEM_256";


// ==========================
// 🧱 Schemas
// ==========================
const BlockSchema = {
  index: Number,
  timestamp: String,
  text: String,
  imageId: String,
  imageHash: String,
  previousHash: String,
  hash: String,
  status: { type: String, default: "Valid" }
};

const PublicBlock = mongoose.model("publicChain", BlockSchema);
const MasterBlock = mongoose.model("masterChain", BlockSchema);

const Meta = mongoose.model("metaData", { key: String, value: String }); 

const User = mongoose.model("UX", {
  username: String,
  password: String,
  role: String
});

const RestoreRequest = mongoose.model("restoreRequests", {
  user: String,
  blockIndex: Number,
  reason: String,
  status: { type: String, default: "Pending" },
  time: String
});

const Activity = mongoose.model("logs", {
  user: String,
  action: String,
  time: String
});


// ==========================
// 👤 Default Login Accounts
// ==========================
if (await User.countDocuments() === 0) {
  await User.create({ username: "admin", password: "admin123", role: "admin" });
  await User.create({ username: "staff", password: "staff123", role: "staff" });

  console.log("✔ Default Users: admin/admin123 | staff/staff123");
}


// ==========================
// 🔐 Auth Middleware
// ==========================
function auth(role = null) {
  return (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.json({ error: "Login Required" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role)
        return res.json({ error: "Access Denied" });

      req.user = decoded;
      next();
    } catch {
      res.json({ error: "Session Expired" });
    }
  };
}


// ==========================
// 🔑 Login Route
// ==========================
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const u = await User.findOne({ username });
  if (!u) return res.json({ error: "User Not Found" });
  if (password !== u.password) return res.json({ error: "Wrong Password" });

  const token = jwt.sign({ username: u.username, role: u.role }, JWT_SECRET);

  await Activity.create({ user: u.username, action: "Logged In", time: new Date().toISOString() });

  res.json({ token, role: u.role });
});


// ==========================
// 🚪 Logout
// ==========================
app.post("/auth/logout", auth(), async (req, res) => {
  await Activity.create({ user: req.user.username, action: "Logged Out", time: new Date().toISOString() });
  res.json({ done: true });
});


// ==========================
// 📌 Get latest block
// ==========================
async function latestBlock() {
  return await PublicBlock.findOne().sort({ index: -1 });
}


// ==========================
// ➕ Add Block  (Staff Only)
// ==========================
app.post("/addBlock", auth("staff"), upload.single("image"), async (req, res) => {
  try {
    if (!bucket) return res.json({ error: "Storage Warming — Try again" });

    let imgHash = "", imgId = "";
    if (req.file) {
      imgHash = hashGen(req.file.buffer);
      const stream = bucket.openUploadStream(Date.now() + "_" + req.file.originalname);
      stream.end(req.file.buffer);
      imgId = stream.id.toString();
    }

    const prev = await latestBlock();
    const index = prev ? prev.index + 1 : 1;
    const timestamp = new Date().toISOString();
    const prevHash = prev ? prev.hash : "0";

    const newHash = hashGen(Buffer.from(req.body.text + imgHash + timestamp + prevHash));

    const block = { index, timestamp, text: req.body.text, imageId: imgId, imageHash: imgHash, previousHash: prevHash, hash: newHash };

    await PublicBlock.create(block);
    await MasterBlock.create(block);

    await Meta.findOneAndUpdate({ key: "lastHash" }, { value: newHash }, { upsert: true });

    res.json({ success: true });
  } catch (err) {
    res.json({ error: "Upload Error" });
  }
});


// ==========================
// 🧾 Staff Chain (Limited)
// ==========================
app.get("/chain/staff", auth("staff"), async (req, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  res.json(chain.map(b => ({ index: b.index, timestamp: b.timestamp, text: b.text, status: b.status })));
});


// ==========================
// 👑 Admin Full Chain
// ==========================
app.get("/chain/admin", auth("admin"), async (req, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});


// ==========================
// 🧊 Freeze Block (Admin)
// ==========================
app.post("/freeze/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "Frozen" });
  res.json({ done: true });
});


// ==========================
// ⚠ Invalidate Block
// ==========================
app.post("/invalidate/:id", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.id }, { status: "Invalidated" });
  res.json({ done: true });
});


// ==========================
// 🛠 Restore System
// ==========================
app.post("/restore/request", auth("staff"), async (req, res) => {
  await RestoreRequest.create({
    user: req.user.username,
    blockIndex: req.body.blockIndex,
    reason: req.body.reason,
    time: new Date().toISOString()
  });

  res.json({ sent: true });
});

app.get("/restore/requests", auth("admin"), async (req, res) => {
  res.json(await RestoreRequest.find());
});

app.post("/restore/approve/:id", auth("admin"), async (req, res) => {
  const reqObj = await RestoreRequest.findById(req.params.id);

  const full = await MasterBlock.find().sort({ index: 1 });
  await PublicBlock.deleteMany({});
  for (let b of full) await PublicBlock.create(JSON.parse(JSON.stringify(b)));

  reqObj.status = "Approved";
  await reqObj.save();

  res.json({ restored: true });
});

app.post("/restore/reject/:id", auth("admin"), async (req, res) => {
  await RestoreRequest.findByIdAndUpdate(req.params.id, { status: "Rejected" });
  res.json({ rejected: true });
});


// ==========================
// 🔍 Validate Blockchain
// ==========================
app.get("/validate", auth(), async (req, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const meta = await Meta.findOne({ key: "lastHash" });

  if (!chain.length) return res.json({ valid: true, msg: "🟢 Blockchain Empty but Safe" });

  for (let i = 0; i < chain.length; i++)
    if (chain[i].index !== i + 1)
      return res.json({ valid: false, msg: `🚨 Block Missing at Position ${i + 1}` });

  if (meta.value !== chain.at(-1).hash)
    return res.json({ valid: false, msg: "🚨 Tampering Attempt Detected" });

  res.json({ valid: true, msg: "✔ Blockchain Verified — No Tampering" });
});


// ==========================
// 🖼 Reveal Image (Admin Only)
// ==========================
app.get("/reveal/:id", auth("admin"), (req, res) => {
  try {
    bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id)).pipe(res);
  } catch {
    res.send("File Missing");
  }
});


// ==========================
// 📜 Activity Logs
// ==========================
app.get("/logs", auth("admin"), async (req, res) => {
  res.json(await Activity.find().sort({ _id: -1 }).limit(50));
});


// ==========================
// 🚀 START SERVER
// ==========================
app.listen(10000, () => console.log("🚀 Blockchain Evidence System Running on Port 10000"));
