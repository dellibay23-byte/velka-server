import express from "express";
import cors from "cors";
import { DatabaseSync } from "node:sqlite";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const TURNSTILE_HOSTNAMES = new Set(["localhost", "127.0.0.1"]);

const db = new DatabaseSync("db.sqlite");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    reg_date TEXT NOT NULL,
    hwid TEXT NOT NULL DEFAULT '-'
  );
`);

async function verifyTurnstile(token, ip, expectedAction) {
  if (typeof token !== "string" || token.length === 0 || token.length > 2048) {
    return false;
  }
  let result;
  try {
    const r = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        signal: AbortSignal.timeout(10_000),
        body: new URLSearchParams({
          secret: TURNSTILE_SECRET,
          response: token,
          remoteip: ip,
        }),
      }
    );
     if (!r.ok) return false;
    result = await r.json();
    console.log("Turnstile verify result:", JSON.stringify(result));
  } catch {
    return false;
  }
  if (!result.success) return false;
  if (expectedAction && result.action && result.action !== expectedAction) return false;
    if (!TURNSTILE_HOSTNAMES.has(result.hostname)) {
    console.log("Hostname mismatch. Got:", result.hostname, "Expected:", [...TURNSTILE_HOSTNAMES]);
    return false;
  }
  return true;
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return res.status(401).json({ message: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body || {};
const tokenFromBody = req.body?.turnstileToken;
const tokenFromHeader = req.headers["cf-turnstile-token"];
const turnstileToken = tokenFromBody || tokenFromHeader;
  if (!username || !email || !password) {
    return res.status(400).json({ message: "username, email, password required" });
  }
  if (password.length < 8) {
    return res.status(400).json({ message: "Пароль должен быть минимум 8 символов" });
  }
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ok = await verifyTurnstile(turnstileToken, ip, null);
  if (!ok) {
    return res.status(403).json({ message: "Ошибка капчи. Попробуй ещё раз." });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare(
      "INSERT INTO users (username, email, password_hash, role, reg_date) VALUES (?, ?, ?, 'USER', ?)"
    );
    const info = stmt.run(username, email, hash, new Date().toISOString());
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
    return res.json({
      message: "Аккаунт создан",
      token: makeToken(user),
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) {
      return res.status(409).json({ message: "Такой username или email уже занят" });
    }
    return res.status(500).json({ message: "Ошибка сервера" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
const tokenFromBody = req.body?.turnstileToken;
const tokenFromHeader = req.headers["cf-turnstile-token"];
const turnstileToken = tokenFromBody || tokenFromHeader;
  if (!username || !password) {
    return res.status(400).json({ message: "username, password required" });
  }
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ok = await verifyTurnstile(turnstileToken, ip, null);
  if (!ok) {
    return res.status(403).json({ message: "Ошибка капчи. Попробуй ещё раз." });
  }
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    return res.status(401).json({ message: "Неверный логин или пароль" });
  }
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ message: "Неверный логин или пароль" });
  }
  return res.json({
    token: makeToken(user),
    user: { id: user.id, username: user.username, email: user.email, role: user.role },
  });
});

app.get("/api/user/profile", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  return res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    regDate: user.reg_date,
    hwid: user.hwid,
  });
});

app.post("/api/user/sub", authMiddleware, (req, res) => {
  return res.json({ sub: { outDate: null, entDate: null } });
});

app.get("/api/user/getHwid", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT hwid FROM users WHERE id = ?").get(req.user.id);
  return res.json({ hwid: user?.hwid || "-" });
});

app.post("/api/auth/forgot-password", (req, res) => {
  return res.json({ message: "Инструкция отправлена на e-mail (заглушка)" });
});

app.get("/", (req, res) => {
  res.send("Velka server работает.");
});

app.listen(PORT, () => {
  console.log(`Сервер: http://localhost:${PORT}`);
  console.log(`Turnstile secret: ${TURNSTILE_SECRET ? "загружен" : "НЕ НАЙДЕН"}`);
});