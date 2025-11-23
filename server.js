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
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const JWT_SECRET = "SUPER_SECRET_KEY";

// ---------- FORCE LOGIN ON ROOT ----------
app.get("/", (req, res) => {
  res.sendFile(process.cwd() + "/public/login.html");
});

// ---------- DB ----------
await mongoose.connect(process.env.MONGO_URL);
console.log("🔥 MongoDB Connected");

// ---------- GRIDFS ----------
let bucket;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📁 GridFS Ready");
});

// ---------- STORAGE ----------
const upload = multer({ storage: multer.memoryStorage() });
const generateHash = data => crypto.createHash("sha256").update(data).digest("hex");

// ---------- MODELS ----------
const blockSchema = {
  index: Number,
  timestamp: String,
  text: String,
  imageHash: String,
  imageId: String,
  previousHash: String,
  hash: String,
  status: { type: String, default: "valid" }
};

const PublicBlock = mongoose.model("publicBlocks", blockSchema);
const MasterBlock = mongoose.model("masterBlocks", blockSchema);

const Meta = mongoose.model("metaRecords", { key: String, value: String });

const User = mongoose.model("UX", {
  username: String,
  password: String,
  role: String
});

const Logs = mongoose.model("userLogs", {
  username: String,
  action: String,
  timestamp: String
});

const RestoreRequest = mongoose.model("restoreRequests", {
  user: String,
  blockIndex: Number,
  reason: String,
  status: { type: String, default: "pending" },
  timestamp: String
});

// ---------- DEFAULT ACCOUNTS ----------
(async () => {
  if (await User.countDocuments() === 0) {
    await User.create({ username: "admin", password: "admin123", role: "admin" });
    await User.create({ username: "staff", password: "staff123", role: "staff" });
    console.log("👤 Default users created.");
  }
})();

// ---------- AUTH MIDDLEWARE ----------
function auth(role) {
  return (req, res, next) => {
    let token = req.headers.authorization;
    if (!token) return res.json({ error: "No Token" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.json({ error: "Access Denied" });

      req.user = decoded;
      next();
    } catch {
      return res.json({ error: "Invalid Token" });
    }
  };
}

// ---------- LOGIN ----------
app.post("/auth/login", async (req, res) => {
  let { username, password } = req.body;
  let u = await User.findOne({ username });

  if (!u) return res.json({ error: "User not found" });
  if (password !== u.password) return res.json({ error: "Wrong password" });

  const token = jwt.sign({ username, role: u.role }, JWT_SECRET);

  await Logs.create({
    username,
    action: "LOGIN",
    timestamp: new Date().toISOString()
  });

  res.json({ token, role: u.role });
});

// ---------- LOGOUT ----------
app.post("/auth/logout", auth(), async (req, res) => {
  await Logs.create({
    username: req.user.username,
    action: "LOGOUT",
    timestamp: new Date().toISOString()
  });
  res.json({ logout: true });
});

// ---------- BLOCKCHAIN CORE ----------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

app.post("/addBlock", auth("staff"), upload.single("image"), async (req, res) => {
  try {
    let imageId = "";
    let imageHash = "";

    if (req.file) {
      imageHash = generateHash(req.file.buffer);
      let stream = bucket.openUploadStream(Date.now()+"-"+req.file.originalname);
      stream.end(req.file.buffer);
      imageId = stream.id.toString();
    }

    let prev = await getLatest();
    let index = prev ? prev.index + 1 : 1;
    let timestamp = new Date().toISOString();
    let previousHash = prev ? prev.hash : "0";
    let hash = generateHash(req.body.text + imageHash + timestamp + previousHash);

    const block = { index, timestamp, text: req.body.text, imageHash, imageId, previousHash, hash };

    await PublicBlock.create(block);
    await MasterBlock.create(block);

    await Meta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

    res.json({ success: true, block });
  } catch (err) {
    res.json({ error: "Block add failed" });
  }
});

// ---------- FETCH CHAIN ----------
app.get("/chain", auth("staff"), async (_, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// ---------- ADMIN FULL CHAIN ----------
app.get("/chain/admin", auth("admin"), async (_, res) => {
  res.json(await PublicBlock.find().sort({ index: 1 }));
});

// ---------- ADMIN ACTIONS ----------
app.post("/freeze/:i", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.i }, { status: "frozen" });
  res.json({ ok: true });
});

app.post("/invalidate/:i", auth("admin"), async (req, res) => {
  await PublicBlock.updateOne({ index: req.params.i }, { status: "invalid" });
  res.json({ ok: true });
});

// ---------- VALIDATION ----------
app.get("/validate", auth(), async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const meta = await Meta.findOne({ key: "lastHash" });

  for (let i = 0; i < chain.length; i++)
    if (chain[i].index !== i+1) return res.json({ valid:false, issue:`Block Missing: ${i+1}` });

  for (let i = 1; i < chain.length; i++)
    if (chain[i].previousHash !== chain[i-1].hash)
      return res.json({ valid:false, issue:`Tampered at block ${i}`});

  if (meta && chain.length && meta.value !== chain[chain.length-1].hash)
    return res.json({ valid:false, issue:"Last block removed" });

  res.json({ valid:true });
});

// ---------- RESTORE REQUEST ----------
app.post("/restore/request", auth("staff"), async (req, res) => {
  await RestoreRequest.create({
    user: req.user.username,
    blockIndex: req.body.blockIndex,
    reason: req.body.reason,
    timestamp: new Date().toISOString()
  });

  res.json({ message:"Restore request sent" });
});

app.get("/restore/requests", auth("admin"), async (_, res) => {
  res.json(await RestoreRequest.find());
});

app.post("/restore/approve/:id", auth("admin"), async (req, res) => {
  let r = await RestoreRequest.findById(req.params.id);

  let master = await MasterBlock.find().sort({ index:1 });
  await PublicBlock.deleteMany({});
  for (let b of master) await PublicBlock.create(JSON.parse(JSON.stringify(b)));

  r.status = "approved";
  await r.save();
  res.json({ restored:true });
});

app.post("/restore/reject/:id", auth("admin"), async (req, res) => {
  await RestoreRequest.findByIdAndUpdate(req.params.id, { status:"rejected" });
  res.json({ rejected:true });
});

// ---------- IMAGE VIEW (ADMIN ONLY) ----------
app.get("/reveal/:id", auth("admin"), (req, res) => {
  try {
    bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id)).pipe(res);
  } catch {
    res.status(404).send("Image Not Found");
  }
});

// ---------- LOG HISTORY ----------
app.get("/logs", auth("admin"), async (_, res) => {
  res.json(await Logs.find().sort({ timestamp:-1 }));
});

// ---------- SERVER ----------
app.listen(10000, () => console.log("🚀 System running on port 10000"));
