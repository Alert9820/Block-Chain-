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
// DB CONNECT (Single connection)
// -------------------------------
await mongoose.connect(process.env.MONGO_URL);
console.log("MongoDB Connected");

// -------------------------------
// GRIDFS
// -------------------------------
let bucket;
mongoose.connection.once("open", () => {
  bucket = new GridFSBucket(mongoose.connection.db, { bucketName: "evidenceFiles" });
  console.log("GridFS Ready");
});

// -------------------------------
// Utilities
// -------------------------------
const generateHash = (data) =>
  crypto.createHash("sha256").update(data).digest("hex");

const storage = multer.memoryStorage();
const upload = multer({ storage });

// -------------------------------
// Schemas / Models (Collections)
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

// 2 logical DB layers using different collections
const PublicBlock = mongoose.model("publicBlocks", BlockSchema);
const MasterBlock = mongoose.model("masterBlocks", BlockSchema);

const Meta = mongoose.model("metaRecords", new mongoose.Schema({
  key: String,
  value: String
}));

// -------------------------------
// GET LAST BLOCK
// -------------------------------
async function getLatest() {
  return await PublicBlock.findOne().sort({ index: -1 });
}

// -------------------------------
// ADD BLOCK
// -------------------------------
app.post("/addBlock", upload.single("image"), async (req, res) => {
  try {
    const { text } = req.body;
    let imageHash = "";
    let imageId = "";

    if (req.file) {
      imageHash = generateHash(req.file.buffer);

      const uploadStream = bucket.openUploadStream(Date.now() + "-" + req.file.originalname);
      uploadStream.end(req.file.buffer);

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

    // store in both logical DB layers
    await PublicBlock.create(newBlock);
    await MasterBlock.create(newBlock);

    await Meta.findOneAndUpdate(
      { key: "lastHash" },
      { value: hash },
      { upsert: true }
    );

    res.json({ success: true, message: "Block added", block: newBlock });

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Failed to add block" });
  }
});

// -------------------------------
// CHAIN FETCH
// -------------------------------
app.get("/chain", async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  res.json(chain);
});

// -------------------------------
// FREEZE / INVALIDATE
// -------------------------------
app.post("/freeze/:i", async (req,res)=>{
  await PublicBlock.updateOne({ index:req.params.i },{ status:"frozen" });
  res.json({ ok:true });
});

app.post("/invalidate/:i", async (req,res)=>{
  await PublicBlock.updateOne({ index:req.params.i },{ status:"invalid" });
  res.json({ ok:true });
});

// -------------------------------
// VALIDATE
// -------------------------------
app.get("/validate", async (_, res) => {
  const chain = await PublicBlock.find().sort({ index: 1 });
  const meta = await Meta.findOne({ key: "lastHash" });

  // Missing block detection
  for (let i=0;i<chain.length;i++){
    if(chain[i].index !== i+1){
      return res.json({ valid:false, reason:"Block missing", index:i+1 });
    }
  }

  // Hash linking check
  for (let i=1;i<chain.length;i++){
    if(chain[i].previousHash !== chain[i-1].hash){
      return res.json({ valid:false, reason:"Tampered", at:i });
    }
  }

  if(chain.length && meta && meta.value !== chain[chain.length-1].hash){
    return res.json({ valid:false, reason:"Last block removed" });
  }

  res.json({ valid:true });
});

// -------------------------------
// RESTORE FROM MASTER
// -------------------------------
app.post("/restore", async (_, res)=>{
  await PublicBlock.deleteMany({});
  const masterData = await MasterBlock.find().sort({ index:1 });

  for(let b of masterData){
    await PublicBlock.create(JSON.parse(JSON.stringify(b)));
  }

  res.json({ restored:true, count:masterData.length });
});

// -------------------------------
app.get("/file/:id",(req,res)=>{
  try{
    const stream = bucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.id));
    stream.on("error",()=>res.status(404).send("File missing"));
    stream.pipe(res);
  }catch{
    res.status(404).send("Invalid ID");
  }
});

// -------------------------------
app.listen(10000,()=>console.log("🚀 Running on port 10000"));
