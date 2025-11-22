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
// DB CONNECT (Single URI)
// -------------------------------
console.log("⏳ Connecting to MongoDB...");

await mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("🔥 MongoDB Connected"))
  .catch(err => console.log("❌ DB Error:", err));

// -------------------------------
// GRIDFS INIT
// -------------------------------
let bucket = null;

mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("📦 GridFS Ready");
});

// -------------------------------
// HELPERS
// -------------------------------
const generateHash = data =>
  crypto.createHash("sha256").update(data).digest("hex");

const storage = multer.memoryStorage();
const upload = multer({ storage });

// -------------------------------
// COLLECTION SCHEMAS
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

const PublicBlock = mongoose.model("publicBlocks", BlockSchema);
const MasterBlock = mongoose.model("masterBlocks", BlockSchema);

const Meta = mongoose.model("metaRecords", new mongoose.Schema({
  key: String,
  value: String
}));


// -------------------------------
// GET LATEST PUBLIC BLOCK
// -------------------------------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}


// -------------------------------
// ADD BLOCK (TEXT + IMAGE OPTIONAL)
// -------------------------------
app.post("/addBlock", upload.single("image"), async (req, res) => {
  try {
    const { text } = req.body;
    let imageHash = "";
    let imageId = "";

    // Store file if exists
    if (req.file) {
      if (!bucket) {
        return res.status(500).json({ error: "⚠ Storage initializing, try again." });
      }

      imageHash = generateHash(req.file.buffer);

      const uploadStream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
      uploadStream.end(req.file.buffer);

      uploadStream.on("finish", () => console.log("📁 File stored:", uploadStream.id));

      imageId = uploadStream.id.toString();
    }

    const latest = await getLatest();
    const index = latest ? latest.index + 1 : 1;
    const previousHash = latest ? latest.hash : "0";
    const timestamp = new Date().toISOString();

    const hash = generateHash(text + imageHash + timestamp + previousHash);

    const newBlock = {
      index,
      timestamp,
      text,
      imageHash,
      imageId,
      previousHash,
      hash,
      status: "valid"
    };

    // Store block in BOTH logical layers
    await PublicBlock.create(newBlock);
    await MasterBlock.create(newBlock);

    // Save last hash
    await Meta.findOneAndUpdate({ key: "lastHash" }, { value: hash }, { upsert: true });

    res.json({ success: true, block: newBlock });

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "❌ Failed to add block" });
  }
});


// -------------------------------
// GET CHAIN
// -------------------------------
app.get("/chain", async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  res.json(chain);
});


// -------------------------------
// STATUS UPDATE ROUTES
// -------------------------------
app.post("/freeze/:i", async (req,res)=>{
  await PublicBlock.updateOne({ index:req.params.i },{ status:"frozen" });
  res.json({ success:true });
});

app.post("/invalidate/:i", async (req,res)=>{
  await PublicBlock.updateOne({ index:req.params.i },{ status:"invalid" });
  res.json({ success:true });
});


// -------------------------------
// VALIDATE CHAIN
// -------------------------------
app.get("/validate", async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const meta = await Meta.findOne({ key: "lastHash" });

  // Missing Block Check
  for (let i=0;i<chain.length;i++){
    if(chain[i].index !== i+1){
      return res.json({ valid:false, reason:`Block #${i+1} missing` });
    }
  }

  // Hash Linking Check
  for (let i=1;i<chain.length;i++){
    if(chain[i].previousHash !== chain[i-1].hash){
      return res.json({ valid:false, reason:`Tampered at block #${i}` });
    }
  }

  // Last block removed detection
  if(chain.length && meta && meta.value !== chain[chain.length-1].hash){
    return res.json({ valid:false, reason:"Last block deleted" });
  }

  res.json({ valid:true });
});


// -------------------------------
// RESTORE FROM MASTER
// -------------------------------
app.post("/restore", async (_, res)=>{
  await PublicBlock.deleteMany({});
  const masterData = await MasterBlock.find().sort({ index: 1 });

  for (let b of masterData) {
    await PublicBlock.create(JSON.parse(JSON.stringify(b)));
  }

  res.json({ restored:true, total: masterData.length });
});


// -------------------------------
// GET FILE
// -------------------------------
app.get("/file/:id", (req,res) => {
  try {
    const stream = bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id));
    stream.on("error",()=>res.status(404).send("File not found"));
    stream.pipe(res);
  } catch {
    res.status(404).send("Invalid file ID");
  }
});


// -------------------------------
// SERVER START
// -------------------------------
app.listen(10000, () => console.log("🚀 Server Running on Port 10000"));
