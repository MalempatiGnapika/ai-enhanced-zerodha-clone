// ✅ dotenv MUST be first line
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const UserModel = require("./model/UserModel");
const HoldingsModel = require("./model/HoldingsModel");
const PositionsModel = require("./model/PositionsModel");
const OrdersModel = require("./model/OrdersModel");

const app = express();

const PORT = process.env.PORT || 3002;
const MONGO_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/stockproject";
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("❌ FATAL: JWT_SECRET is not set in .env");
  process.exit(1);
}

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ─── MongoDB ───────────────────────────────────────────────────────────────────
mongoose
  .connect(MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB error:", err.message);
    process.exit(1);
  });

// ─── Auth Middleware ───────────────────────────────────────────────────────────
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const tokenFromHeader =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;
  const tokenFromCookie = req.cookies?.token;
  const token = tokenFromHeader || tokenFromCookie;

  if (!token) {
    return res.status(401).json({ success: false, message: "No token. Please log in." });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ success: false, message: "Token invalid or expired." });
  }
};

const setTokenCookie = (res, token) => {
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: "All fields are required." });
    if (password.length < 6)
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters." });

    const existing = await UserModel.findOne({ email: email.toLowerCase().trim() });
    if (existing)
      return res.status(409).json({ success: false, message: "Email already registered." });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new UserModel({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashed,
    });
    await newUser.save();

    const token = jwt.sign(
      { userId: newUser._id, email: newUser.email, name: newUser.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    setTokenCookie(res, token);

    return res.status(201).json({
      success: true,
      message: "Account created!",
      token,
      user: { name: newUser.name, email: newUser.email },
    });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ success: false, message: "Server error during signup." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: "Email and password required." });

    const user = await UserModel.findOne({ email: email.toLowerCase().trim() });
    if (!user)
      return res.status(401).json({ success: false, message: "Invalid email or password." });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ success: false, message: "Invalid email or password." });

    const token = jwt.sign(
      { userId: user._id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    setTokenCookie(res, token);

    return res.status(200).json({
      success: true,
      message: "Login successful!",
      token,
      user: { name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Server error during login." });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  return res.status(200).json({ success: true, message: "Logged out." });
});

app.get("/verify-token", authenticateToken, (req, res) => {
  return res.status(200).json({ success: true, valid: true, user: req.user });
});

// ─── DATA ROUTES ──────────────────────────────────────────────────────────────

app.get("/allHoldings", authenticateToken, async (req, res) => {
  try {
    const data = await HoldingsModel.find({});
    res.json(data);
  } catch (err) {
    console.error("Holdings error:", err);
    res.status(500).json({ message: "Error fetching holdings." });
  }
});

app.get("/allPositions", authenticateToken, async (req, res) => {
  try {
    const data = await PositionsModel.find({});
    res.json(data);
  } catch (err) {
    console.error("Positions error:", err);
    res.status(500).json({ message: "Error fetching positions." });
  }
});

app.post("/newOrder", authenticateToken, async (req, res) => {
  try {
    const { name, qty, price, mode } = req.body;
    const order = new OrdersModel({ name, qty, price, mode });
    await order.save();
    res.status(201).json({ success: true, message: "Order placed!" });
  } catch (err) {
    console.error("Order error:", err);
    res.status(500).json({ message: "Error placing order." });
  }
});

app.get("/allOrders", authenticateToken, async (req, res) => {
  try {
    const data = await OrdersModel.find({});
    res.json(data);
  } catch (err) {
    console.error("Orders error:", err);
    res.status(500).json({ message: "Error fetching orders." });
  }
});

app.post("/ai-assistant", authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || message.trim().length === 0) {
      return res.status(400).json({ success: false, message: "Message cannot be empty." });
    }

    const COHERE_API_KEY = process.env.COHERE_API_KEY;
    if (!COHERE_API_KEY) {
      return res.status(503).json({
        success: false,
        message: "AI not configured. Add COHERE_API_KEY to backend/.env",
      });
    }

    const response = await fetch("https://api.cohere.com/v1/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${COHERE_API_KEY}`,
      },
      body: JSON.stringify({
       model: "command-a-03-2025",
        message: message.trim(),
        preamble: `You are Kite AI, a stock market educational assistant for Indian investors using Zerodha. Answer questions about NSE/BSE stocks, portfolio, P&L, SIP, F&O, mutual funds, SEBI rules, STCG/LTCG tax. Never give specific buy/sell advice. Always add: "Educational only — not financial advice." Keep answers concise and beginner-friendly. Use ₹ and Indian market context.`,
        max_tokens: 400,
        temperature: 0.7,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("Cohere error:", JSON.stringify(data));
      return res.status(502).json({ success: false, message: "AI service error. Please try again." });
    }

    const reply = data?.text || "Sorry, I could not generate a response.";
    return res.json({ success: true, reply });

  } catch (error) {
    console.error("AI assistant error:", error.message);
    return res.status(500).json({ success: false, message: "Server error in AI assistant." });
  }
});
// ─── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Backend running at http://localhost:${PORT}`);
console.log(`   Cohere AI: ${process.env.COHERE_API_KEY ? "✅ Key found" : "❌ COHERE_API_KEY missing in .env"}`);
});