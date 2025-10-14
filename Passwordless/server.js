const express = require("express");
const bodyParser = require("body-parser");
const { Fido2Lib } = require("fido2-lib");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const session = require("express-session");

const app = express();
app.use(bodyParser.json({ limit: "5mb" }));
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
  secret: "fido2-secret-session",
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // ubah ke true jika pakai HTTPS
}));

// ======= KONFIGURASI FIDO2 =======
const RP_ID = "localhost";
const RP_NAME = "Demo FIDO2";
const ORIGIN = "http://localhost:3000";

const f2l = new Fido2Lib({
  timeout: 60000,
  rpId: RP_ID,
  rpName: RP_NAME,
  challengeSize: 64,
  cryptoParams: [-7, -257],
  authenticatorUserVerification: "preferred",
});

// ======= PENYIMPANAN USER JSON =======
const USERS_FILE = path.join(__dirname, "users.json");
let users = new Map();

function loadUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      fs.writeFileSync(USERS_FILE, "[]");
    }
    const data = JSON.parse(fs.readFileSync(USERS_FILE));
    users = new Map(data.map(u => [u.username, u]));
    console.log(`📂 ${users.size} user(s) dimuat dari users.json.`);
  } catch (err) {
    console.error("❌ Gagal membaca users.json, direset ke []:", err.message);
    fs.writeFileSync(USERS_FILE, "[]");
    users = new Map();
  }
}

function saveUsers() {
  try {
    const data = JSON.stringify(Array.from(users.values()), null, 2);
    fs.writeFileSync(USERS_FILE, data);
  } catch (err) {
    console.error("❌ Gagal menyimpan users.json:", err.message);
  }
}

loadUsers();

// ======= UTILITAS =======
function getUser(username) {
  return users.get(username);
}
function createUser(username) {
  const user = {
    id: username + ":" + Date.now(),
    username,
    credentials: [],
    loginCount: 0,
    lastLogin: null,
    pending: true
  };
  users.set(username, user);
  saveUsers();
  return user;
}

function base64urlToArrayBuffer(base64url) {
  base64url = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64url.length % 4 ? 4 - (base64url.length % 4) : 0;
  const base64 = base64url + "=".repeat(pad);
  const binary = Buffer.from(base64, "base64");
  return new Uint8Array(binary).buffer;
}

// ---------------- CEK USERNAME REALTIME ----------------
app.get("/check-username/:username", (req, res) => {
  const username = req.params.username.trim().toLowerCase();
  const exists = users.has(username);
  res.json({ available: !exists });
});

// ---------------- REGISTER ----------------
app.post("/register/options", async (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  if (!username) return res.status(400).json({ error: "username required" });

  const existingUser = getUser(username);
  if (existingUser) {
    return res.status(400).json({
      ok: false,
      error: `Username "${username}" sudah terdaftar.`
    });
  }

  const user = createUser(username);

  // --- PENAMBAHAN FITUR TIMEOUT ---
  // Jadwalkan pembersihan otomatis setelah 2 menit
  setTimeout(() => {
    const userToCheck = getUser(username);
    // Hapus hanya jika pengguna masih ada dan statusnya masih 'pending'
    if (userToCheck && userToCheck.pending) {
      users.delete(username);
      saveUsers();
      console.log(`Pengguna pending "${username}" dihapus karena timeout registrasi.`);
    }
  }, 30000); // Timeout 30 detik (30,000 ms)
  // ---------------------------------

  const opts = await f2l.attestationOptions();
  opts.challenge = Buffer.from(opts.challenge).toString("base64url");
  opts.rp = { id: RP_ID, name: RP_NAME };
  opts.user = {
    id: Buffer.from(user.id).toString("base64url"),
    name: username,
    displayName: username
  };
  opts.attestation = "none";

  user.currentChallenge = opts.challenge;
  saveUsers(); // Simpan challenge ke user

  console.log("Register Options:", JSON.stringify(opts, null, 2));
  res.json(opts);
});

app.post("/register/complete", async (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const { attestationResponse } = req.body;

  try {
    const user = getUser(username);
    if (!user) return res.status(400).json({ ok: false, error: "user not found" });

    const expected = {
      challenge: user.currentChallenge,
      origin: ORIGIN,
      factor: "either",
      rpId: RP_ID
    };

    const rawIdArrayBuffer = base64urlToArrayBuffer(attestationResponse.rawId);
    const attResp = {
      id: rawIdArrayBuffer,
      rawId: rawIdArrayBuffer,
      response: {
        clientDataJSON: base64urlToArrayBuffer(attestationResponse.response.clientDataJSON),
        attestationObject: base64urlToArrayBuffer(attestationResponse.response.attestationObject)
      },
      type: attestationResponse.type
    };

    const result = await f2l.attestationResult(attResp, expected);

    const credId = attestationResponse.rawId;
    const publicKey = result.authnrData.get("credentialPublicKeyPem");
    const counter = result.authnrData.get("counter");

    user.credentials.push({ credId, publicKey, counter });
    user.pending = false; // Registrasi berhasil, user tidak lagi pending
    saveUsers();

    console.log(`✅ Register sukses: ${username}`);
    res.json({ ok: true, message: "Registrasi berhasil!" });
  } catch (err) {
    console.error("❌ Register error:", err);
    
    // Jika error, hapus user pending
    const user = getUser(username);
    if (user && user.pending) {
      users.delete(username);
      saveUsers();
      console.log(`User "${username}" dihapus karena registrasi gagal atau dibatalkan.`);
    }

    res.status(400).json({ ok: false, error: "register failed", detail: err.message });
  }
});

// ---------------- LOGIN ----------------
app.post("/login/options", async (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const user = getUser(username);
  if (!user || user.credentials.length === 0) {
    return res.status(400).json({ error: "user not registered" });
  }

  const opts = await f2l.assertionOptions();
  opts.challenge = Buffer.from(opts.challenge).toString("base64url");
  opts.allowCredentials = user.credentials.map(c => ({
    type: "public-key",
    id: c.credId,
    transports: ["internal", "hybrid"]
  }));

  user.currentChallenge = opts.challenge;
  saveUsers();

  res.json(opts);
});

app.post("/login/complete", async (req, res) => {
  const username = (req.body.username || "").trim().toLowerCase();
  const { assertionResponse } = req.body;

  try {
    const user = getUser(username);
    if (!user) return res.status(400).json({ ok: false, error: "user not found" });

    // Cari kredensial yang cocok berdasarkan rawId yang dikirim dari client
    const cred = user.credentials.find(c => c.credId === assertionResponse.rawId);
    if (!cred) {
      throw new Error("Credential not found for this user.");
    }

    const userHandleBuffer = assertionResponse.response.userHandle ? base64urlToArrayBuffer(assertionResponse.response.userHandle) : null;

    const expected = {
      challenge: user.currentChallenge,
      origin: ORIGIN,
      factor: "either",
      rpId: RP_ID,
      publicKey: cred.publicKey,
      prevCounter: cred.counter,
      userHandle: userHandleBuffer
    };

    const assertResp = {
      id: base64urlToArrayBuffer(assertionResponse.rawId),
      rawId: base64urlToArrayBuffer(assertionResponse.rawId),
      type: "public-key",
      response: {
        clientDataJSON: base64urlToArrayBuffer(assertionResponse.response.clientDataJSON),
        authenticatorData: base64urlToArrayBuffer(assertionResponse.response.authenticatorData),
        signature: base64urlToArrayBuffer(assertionResponse.response.signature),
        userHandle: userHandleBuffer
      }
    };

    const result = await f2l.assertionResult(assertResp, expected);
    const newCounter = result.authnrData.get("counter");
    cred.counter = newCounter ?? cred.counter + 1;

    user.lastLogin = new Date().toISOString();
    user.loginCount = (user.loginCount || 0) + 1;
    saveUsers();

    req.session.username = username;

    console.log(`✅ Login sukses: ${username}, total login: ${user.loginCount}`);
    res.json({ ok: true, message: "Login berhasil!", redirect: "/dashboard.html" });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(400).json({ ok: false, error: "login failed", detail: err.message });
  }
});


// ---------------- DASHBOARD ----------------
app.get("/session", (req, res) => {
  if (req.session.username) {
    const user = getUser(req.session.username);
    res.json({
      loggedIn: true,
      user: user.username,
      lastLogin: user.lastLogin,
      loginCount: user.loginCount
    });
  } else {
    res.json({ loggedIn: false });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ---------------- START SERVER ----------------
app.listen(3000, () => console.log("Server running at http://localhost:3000"));