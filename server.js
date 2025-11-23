import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { GridFSBucket } from "mongodb";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();

// __dirname fix for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const JWT_SECRET = process.env.JWT_SECRET || "SUPER_SECRET_KEY_123";

// ---------- DATABASE CONNECTION ----------
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    console.log("🔥 MongoDB Connected Successfully");
    
    // GridFS setup
    const db = mongoose.connection.db;
    const bucket = new GridFSBucket(db, { bucketName: "evidenceFiles" });
    console.log("📁 GridFS Bucket Ready");
    
    return bucket;
  } catch (error) {
    console.error("❌ Database connection failed:", error);
    process.exit(1);
  }
};

let bucket;
connectDB().then(b => bucket = b);

// ---------- MULTER CONFIG ----------
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// ---------- UTILITY FUNCTIONS ----------
const generateHash = (data) => crypto.createHash("sha256").update(data).digest("hex");

// ---------- MODELS ----------
const blockSchema = new mongoose.Schema({
  index: { type: Number, required: true, unique: true },
  timestamp: { type: String, required: true },
  text: { type: String, required: true },
  imageHash: String,
  imageId: String,
  previousHash: { type: String, required: true },
  hash: { type: String, required: true, unique: true },
  status: { type: String, default: "valid", enum: ["valid", "frozen", "invalid"] }
}, { timestamps: true });

const PublicBlock = mongoose.model("PublicBlock", blockSchema);
const MasterBlock = mongoose.model("MasterBlock", blockSchema);

const metaSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: { type: String, required: true }
});
const Meta = mongoose.model("Meta", metaSchema);

// ✅ UX MODEL USE KARO - Aapke existing collection ke liye
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true, enum: ["admin", "staff"] }
});
const User = mongoose.model("UX", userSchema); // ✅ UX collection use karo

const logSchema = new mongoose.Schema({
  username: { type: String, required: true },
  action: { type: String, required: true },
  timestamp: { type: String, required: true },
  ip: String
}, { timestamps: true });
const Log = mongoose.model("Log", logSchema);

const restoreRequestSchema = new mongoose.Schema({
  user: { type: String, required: true },
  blockIndex: { type: Number, required: true },
  reason: { type: String, required: true },
  status: { type: String, default: "pending", enum: ["pending", "approved", "rejected"] },
  timestamp: { type: String, required: true }
}, { timestamps: true });
const RestoreRequest = mongoose.model("RestoreRequest", restoreRequestSchema);

// ---------- INITIAL SETUP ----------
const initializeDefaults = async () => {
  try {
    // ✅ UX model use karo
    const userCount = await User.countDocuments();
    console.log("🔍 Current users in UX collection:", userCount);
    
    if (userCount === 0) {
      await User.create([
        { username: "admin", password: "admin123", role: "admin" },
        { username: "staff", password: "staff123", role: "staff" }
      ]);
      console.log("✅ Default users created in UX collection");
      
      // Debug: Print created users
      const createdUsers = await User.find({});
      console.log("📋 Created users:", createdUsers);
    } else {
      // Debug: Print existing users
      const existingUsers = await User.find({});
      console.log("📋 Existing users in UX:", existingUsers);
    }
    
    // Create genesis block if doesn't exist
    const genesisExists = await PublicBlock.findOne({ index: 0 });
    if (!genesisExists) {
      const genesisBlock = {
        index: 0,
        timestamp: new Date().toISOString(),
        text: "GENESIS BLOCK - SYSTEM INITIALIZED",
        imageHash: "",
        imageId: "",
        previousHash: "0",
        hash: generateHash("genesis" + Date.now())
      };
      
      await PublicBlock.create(genesisBlock);
      await MasterBlock.create(genesisBlock);
      console.log("🔗 Genesis block created");
    }
  } catch (error) {
    console.error("💥 Initialization error:", error);
  }
};

// ---------- AUTH MIDDLEWARE ----------
const authenticate = (requiredRole = null) => {
  return async (req, res, next) => {
    try {
      const token = req.headers.authorization;
      if (!token) {
        return res.status(401).json({ error: "Access token required" });
      }

      const decoded = jwt.verify(token, JWT_SECRET);
      
      // ✅ UX model use karo
      const user = await User.findOne({ username: decoded.username });
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }

      if (requiredRole && user.role !== requiredRole) {
        return res.status(403).json({ error: "Insufficient permissions" });
      }

      req.user = user;
      next();
    } catch (error) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
};

// ---------- LOGGING MIDDLEWARE ----------
const logAction = async (username, action, req) => {
  try {
    await Log.create({
      username,
      action,
      timestamp: new Date().toISOString(),
      ip: req.ip || req.connection.remoteAddress
    });
  } catch (error) {
    console.error("Logging failed:", error);
  }
};

// ---------- ROUTES ----------

// Root route - redirect to login
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Health check
app.get("/health", (req, res) => {
  res.json({ 
    status: "OK", 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? "connected" : "disconnected"
  });
});

// ---------- DEBUG ROUTES ----------
app.get("/debug-db", async (req, res) => {
  try {
    const allUsers = await User.find({});
    const allBlocks = await PublicBlock.find({});
    
    console.log("🔍 DEBUG - UX Collection:", allUsers);
    console.log("🔍 DEBUG - PublicBlocks:", allBlocks);
    
    res.json({ 
      collection: "UX",
      users: allUsers,
      blocks: allBlocks,
      userCount: allUsers.length,
      blockCount: allBlocks.length
    });
  } catch (error) {
    console.error("💥 DATABASE DEBUG ERROR:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------- AUTH ROUTES ----------
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log("🔐 LOGIN ATTEMPT - Username:", username);
    
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    // ✅ UX model use karo
    const user = await User.findOne({ username });
    console.log("👤 FOUND USER:", user);

    if (!user) {
      console.log("❌ USER NOT FOUND");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    console.log("🔑 INPUT PASSWORD:", password);
    console.log("🔑 STORED PASSWORD:", user.password);
    console.log("🔑 PASSWORDS MATCH:", password === user.password);

    if (password !== user.password) {
      console.log("❌ WRONG PASSWORD");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    console.log("✅ LOGIN SUCCESSFUL");

    const token = jwt.sign(
      { username: user.username, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: "24h" }
    );

    await logAction(username, "LOGIN", req);

    res.json({ 
      success: true, 
      token, 
      role: user.role,
      username: user.username
    });
  } catch (error) {
    console.error("💥 Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// ✅ TEST LOGIN ROUTE (Backup ke liye)
app.post("/auth/login-test", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log("🧪 TEST LOGIN - Username:", username);

    // Direct hardcoded check
    if (username === "admin" && password === "admin123") {
      const token = jwt.sign({ username, role: "admin" }, JWT_SECRET);
      return res.json({ success: true, token, role: "admin", username });
    }
    if (username === "staff" && password === "staff123") {
      const token = jwt.sign({ username, role: "staff" }, JWT_SECRET);
      return res.json({ success: true, token, role: "staff", username });
    }

    console.log("❌ TEST LOGIN FAILED");
    return res.status(401).json({ error: "Invalid credentials" });
    
  } catch (error) {
    console.error("💥 TEST LOGIN ERROR:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/auth/logout", authenticate(), async (req, res) => {
  try {
    await logAction(req.user.username, "LOGOUT", req);
    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ error: "Logout failed" });
  }
});

// ---------- BLOCKCHAIN ROUTES ----------
app.post("/addBlock", authenticate("staff"), upload.single("image"), async (req, res) => {
  try {
    const { text } = req.body;
    
    if (!text || !text.trim()) {
      return res.status(400).json({ error: "Evidence text is required" });
    }

    let imageId = null;
    let imageHash = "";

    // Handle image upload
    if (req.file) {
      try {
        imageHash = generateHash(req.file.buffer);
        const uploadStream = bucket.openUploadStream(
          `${Date.now()}-${req.file.originalname}`
        );
        
        uploadStream.end(req.file.buffer);
        imageId = uploadStream.id.toString();
      } catch (fileError) {
        console.error("File upload error:", fileError);
        return res.status(500).json({ error: "Image upload failed" });
      }
    }

    // Get latest block and create new one
    const latestBlock = await PublicBlock.findOne().sort({ index: -1 });
    const index = latestBlock ? latestBlock.index + 1 : 1;
    const timestamp = new Date().toISOString();
    const previousHash = latestBlock ? latestBlock.hash : "0";
    
    const hashData = text + imageHash + timestamp + previousHash;
    const hash = generateHash(hashData);

    const newBlock = {
      index,
      timestamp,
      text: text.trim(),
      imageHash,
      imageId,
      previousHash,
      hash
    };

    // Save to both public and master chains
    await Promise.all([
      PublicBlock.create(newBlock),
      MasterBlock.create(newBlock)
    ]);

    // Update last hash in meta
    await Meta.findOneAndUpdate(
      { key: "lastHash" },
      { value: hash },
      { upsert: true }
    );

    await logAction(req.user.username, `ADD_BLOCK_${index}`, req);

    res.json({ 
      success: true, 
      block: newBlock,
      message: "Evidence block added successfully"
    });

  } catch (error) {
    console.error("Add block error:", error);
    
    if (error.code === 11000) {
      return res.status(409).json({ error: "Block already exists" });
    }
    
    res.status(500).json({ error: "Failed to add evidence block" });
  }
});

app.get("/chain", authenticate("staff"), async (req, res) => {
  try {
    const chain = await PublicBlock.find()
      .select('-imageId -previousHash -hash')
      .sort({ index: 1 });
    
    res.json(chain);
  } catch (error) {
    console.error("Get chain error:", error);
    res.status(500).json({ error: "Failed to fetch blockchain" });
  }
});

app.get("/chain/admin", authenticate("admin"), async (req, res) => {
  try {
    const chain = await PublicBlock.find().sort({ index: 1 });
    res.json(chain);
  } catch (error) {
    console.error("Get admin chain error:", error);
    res.status(500).json({ error: "Failed to fetch blockchain" });
  }
});

// ---------- ADMIN ACTIONS ----------
app.post("/freeze/:index", authenticate("admin"), async (req, res) => {
  try {
    const { index } = req.params;
    
    const block = await PublicBlock.findOneAndUpdate(
      { index: parseInt(index) },
      { status: "frozen" },
      { new: true }
    );

    if (!block) {
      return res.status(404).json({ error: "Block not found" });
    }

    await logAction(req.user.username, `FREEZE_BLOCK_${index}`, req);
    
    res.json({ 
      success: true, 
      message: `Block ${index} frozen successfully`,
      block 
    });
  } catch (error) {
    console.error("Freeze error:", error);
    res.status(500).json({ error: "Failed to freeze block" });
  }
});

app.post("/invalidate/:index", authenticate("admin"), async (req, res) => {
  try {
    const { index } = req.params;
    
    const block = await PublicBlock.findOneAndUpdate(
      { index: parseInt(index) },
      { status: "invalid" },
      { new: true }
    );

    if (!block) {
      return res.status(404).json({ error: "Block not found" });
    }

    await logAction(req.user.username, `INVALIDATE_BLOCK_${index}`, req);
    
    res.json({ 
      success: true, 
      message: `Block ${index} invalidated successfully`,
      block 
    });
  } catch (error) {
    console.error("Invalidate error:", error);
    res.status(500).json({ error: "Failed to invalidate block" });
  }
});

// ---------- VALIDATION ----------
app.get("/validate", authenticate(), async (req, res) => {
  try {
    const chain = await PublicBlock.find().sort({ index: 1 });
    
    if (chain.length === 0) {
      return res.json({ valid: true, message: "Empty chain" });
    }

    // Check block sequence
    for (let i = 0; i < chain.length; i++) {
      if (chain[i].index !== i) {
        return res.json({ 
          valid: false, 
          issue: `Block sequence broken at index ${i}`,
          tamperedAt: i 
        });
      }
    }

    // Check hash links
    for (let i = 1; i < chain.length; i++) {
      if (chain[i].previousHash !== chain[i-1].hash) {
        return res.json({ 
          valid: false, 
          issue: `Hash mismatch at block ${i}`,
          tamperedAt: i 
        });
      }
    }

    // Check last hash
    const meta = await Meta.findOne({ key: "lastHash" });
    if (meta && chain.length > 0 && meta.value !== chain[chain.length-1].hash) {
      return res.json({ 
        valid: false, 
        issue: "Last block removed or tampered",
        tamperedAt: chain.length - 1 
      });
    }

    res.json({ 
      valid: true, 
      message: "Blockchain integrity verified",
      blockCount: chain.length 
    });
  } catch (error) {
    console.error("Validation error:", error);
    res.status(500).json({ error: "Validation failed" });
  }
});

// ---------- RESTORE SYSTEM ----------
app.post("/restore/request", authenticate("staff"), async (req, res) => {
  try {
    const { blockIndex, reason } = req.body;
    
    if (!blockIndex || !reason) {
      return res.status(400).json({ error: "Block index and reason are required" });
    }

    const request = await RestoreRequest.create({
      user: req.user.username,
      blockIndex: parseInt(blockIndex),
      reason: reason.trim(),
      timestamp: new Date().toISOString()
    });

    await logAction(req.user.username, `RESTORE_REQUEST_${blockIndex}`, req);

    res.json({ 
      success: true, 
      message: "Restore request submitted successfully",
      requestId: request._id 
    });
  } catch (error) {
    console.error("Restore request error:", error);
    res.status(500).json({ error: "Failed to submit restore request" });
  }
});

app.get("/restore/requests", authenticate("admin"), async (req, res) => {
  try {
    const requests = await RestoreRequest.find().sort({ createdAt: -1 });
    res.json(requests);
  } catch (error) {
    console.error("Get restore requests error:", error);
    res.status(500).json({ error: "Failed to fetch restore requests" });
  }
});

app.post("/restore/approve/:id", authenticate("admin"), async (req, res) => {
  try {
    const request = await RestoreRequest.findById(req.params.id);
    
    if (!request) {
      return res.status(404).json({ error: "Restore request not found" });
    }

    if (request.status !== "pending") {
      return res.status(400).json({ error: "Request already processed" });
    }

    // Restore from master backup
    const masterChain = await MasterBlock.find().sort({ index: 1 });
    
    // Clear public chain and restore from master
    await PublicBlock.deleteMany({});
    for (const block of masterChain) {
      await PublicBlock.create(block.toObject());
    }

    // Update request status
    request.status = "approved";
    await request.save();

    await logAction(req.user.username, `RESTORE_APPROVED_${request.blockIndex}`, req);

    res.json({ 
      success: true, 
      message: "Blockchain restored successfully from master backup",
      restoredBlocks: masterChain.length 
    });
  } catch (error) {
    console.error("Restore approve error:", error);
    res.status(500).json({ error: "Failed to restore blockchain" });
  }
});

app.post("/restore/reject/:id", authenticate("admin"), async (req, res) => {
  try {
    const request = await RestoreRequest.findByIdAndUpdate(
      req.params.id,
      { status: "rejected" },
      { new: true }
    );

    if (!request) {
      return res.status(404).json({ error: "Restore request not found" });
    }

    await logAction(req.user.username, `RESTORE_REJECTED_${request.blockIndex}`, req);

    res.json({ 
      success: true, 
      message: "Restore request rejected" 
    });
  } catch (error) {
    console.error("Restore reject error:", error);
    res.status(500).json({ error: "Failed to reject restore request" });
  }
});

// ---------- IMAGE ACCESS ----------
app.get("/file/:id", authenticate("admin"), async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    
    const files = await bucket.find({ _id: fileId }).toArray();
    if (files.length === 0) {
      return res.status(404).json({ error: "File not found" });
    }

    res.set('Content-Type', files[0].contentType);
    
    const downloadStream = bucket.openDownloadStream(fileId);
    
    downloadStream.on('error', () => {
      res.status(404).send('File not found');
    });
    
    downloadStream.pipe(res);
    
  } catch (error) {
    console.error("File access error:", error);
    res.status(500).json({ error: "Failed to access file" });
  }
});

// ---------- LOGS ----------
app.get("/logs", authenticate("admin"), async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const logs = await Log.find()
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));
    
    res.json(logs);
  } catch (error) {
    console.error("Get logs error:", error);
    res.status(500).json({ error: "Failed to fetch logs" });
  }
});

// ---------- ERROR HANDLING ----------
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
  }
  
  console.error("Unhandled error:", error);
  res.status(500).json({ error: "Internal server error" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// ---------- SERVER START ----------
const PORT = process.env.PORT || 10000;

app.listen(PORT, async () => {
  await initializeDefaults();
  console.log(`🚀 Evidence Blockchain System running on port ${PORT}`);
  console.log(`📍 Access the system at: http://localhost:${PORT}`);
  console.log(`🔍 Debug database: http://localhost:${PORT}/debug-db`);
});

export default app;
