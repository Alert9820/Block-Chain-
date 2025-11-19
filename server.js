import express from "express";
import mongoose from "mongoose";
import multer from "multer";
import crypto from "crypto";
import cors from "cors";
import Block from "./models/Block.js";

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connect
mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// Image upload
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Generate SHA256 hash
function generateHash(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

// Get latest block
async function getLatestBlock() {
    return await Block.findOne().sort({ index: -1 });
}

// Add block API
app.post("/addBlock", upload.single("image"), async (req, res) => {
    const { text } = req.body;
    let imageHash = "";

    if (req.file) {
        imageHash = generateHash(req.file.buffer);
    }

    const latest = await getLatestBlock();

    const index = latest ? latest.index + 1 : 1;
    const timestamp = new Date().toISOString();
    const previousHash = latest ? latest.hash : "0";

    const combinedData = text + imageHash + timestamp + previousHash;
    const hash = generateHash(combinedData);

    const newBlock = new Block({
        index,
        timestamp,
        text,
        imageHash,
        previousHash,
        hash
    });

    await newBlock.save();
    return res.json({ message: "Block added", block: newBlock });
});

// Get chain
app.get("/chain", async (req, res) => {
    const chain = await Block.find().sort({ index: 1 });
    res.json(chain);
});

// Validate chain
app.get("/validate", async (req, res) => {
    const chain = await Block.find().sort({ index: 1 });

    for (let i = 1; i < chain.length; i++) {
        if (chain[i].previousHash !== chain[i - 1].hash) {
            return res.json({ valid: false, tamperedAt: chain[i].index });
        }
    }

    res.json({ valid: true });
});

app.use(express.static("public"));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
