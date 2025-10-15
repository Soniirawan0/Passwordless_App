// helper: ArrayBuffer → base64url
function bufferToBase64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// helper: base64url → Uint8Array
function base64urlToUint8Array(base64url) {
  if (!base64url) return new Uint8Array(); // ✅ aman kalau kosong
  base64url = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64url.length % 4 ? 4 - (base64url.length % 4) : 0;
  const base64 = base64url + "=".repeat(pad);
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// ---------- REGISTER ----------
async function register(username, log) {
  log("Memulai registrasi untuk: " + username);

  // Kirim permintaan ke server untuk opsi register
  log("[Klien] Meminta opsi registrasi dari server...");
  const res = await fetch("/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const msg = errData.error || "Gagal meminta opsi register dari server";
    log("❌ Gagal: " + msg, "error");
    return;
  }

  const options = await res.json();
  log("[Server] Mengirim challenge dan opsi registrasi.");
  
  // Konversi data dari server
  options.challenge = base64urlToUint8Array(options.challenge);
  options.user.id = base64urlToUint8Array(options.user.id);
  
  log("[Browser] Memanggil `navigator.credentials.create()`...");
  log("Silakan gunakan authenticator Anda untuk verifikasi...");

  try {
    const cred = await navigator.credentials.create({ publicKey: options });
    log("[Authenticator] Kunci publik dan privat berhasil dibuat.");
    
    const credential = {
      id: cred.id,
      rawId: bufferToBase64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
        attestationObject: bufferToBase64url(cred.response.attestationObject)
      }
    };

    log("[Klien] Mengirim kunci publik ke server untuk disimpan...");
    const res2 = await fetch("/register/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, attestationResponse: credential })
    });

    const result = await res2.json();
    
    if (result.ok) {
      log("[Server] Verifikasi berhasil.", "success");
      alert("✅ Register sukses: " + result.message);
    } else {
      log("[Server] Gagal memverifikasi: " + (result.error || "unknown"), "error");
      alert("❌ Register gagal: " + (result.error || "unknown"));
    }
  } catch (err) {
    const cancelMessage = "Pengguna membatalkan registrasi atau terjadi error.";
    log(cancelMessage, "error");
    console.error("❌ Register error:", err);

    // --- TAMBAHAN BARU: SIMULASI PESAN TIMEOUT DARI SERVER ---
    log("Menunggu server membersihkan username yang tertunda (sekitar 30 detik)...", "info");
    setTimeout(() => {
      const timeoutMessage = `[Info Server] Pengguna pending "${username}" dihapus.`;
      log(timeoutMessage, "info");
    }, 30000); // Samakan dengan timeout server
    // --------------------------------------------------------
  }
}

// ---------- LOGIN ----------
async function login(username, log) {
  log("Memulai login untuk: " + username);
  
  log("[Klien] Meminta opsi login dari server...");
  const res = await fetch("/login/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const msg = errData.error || "Gagal meminta opsi login dari server";
    log("❌ Gagal: " + msg, "error");
    return;
  }

  const options = await res.json();
  log("[Server] Mengirim challenge untuk ditandatangani.");

  // Konversi data
  options.challenge = base64urlToUint8Array(options.challenge);
  options.allowCredentials = options.allowCredentials.map(cred => ({
    type: cred.type,
    id: base64urlToUint8Array(cred.id),
    transports: cred.transports
  }));
  
  log("[Browser] Memanggil `navigator.credentials.get()`...");
  log("Silakan gunakan authenticator Anda untuk verifikasi...");
  
  try {
    const assertion = await navigator.credentials.get({ publicKey: options });
    log("[Authenticator] Challenge berhasil ditandatangani dengan kunci privat.");

    const assertionData = {
      id: assertion.id,
      rawId: bufferToBase64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
        signature: bufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? bufferToBase64url(assertion.response.userHandle)
          : null
      }
    };
    
    log("[Klien] Mengirim challenge yang sudah ditandatangani ke server...");
    const res2 = await fetch("/login/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, assertionResponse: assertionData })
    });

    const result = await res2.json();
    
    if (result.ok) {
      log("[Server] Tanda tangan valid.", "success");
      alert("✅ Login sukses: " + result.message);
      if (result.redirect) {
        window.location.href = result.redirect;
      }
    } else {
      log("[Server] Gagal memverifikasi tanda tangan.", "error");
      alert("❌ Login gagal: " + (result.error || "unknown"));
    }
  } catch (err) {
    log("Pengguna membatalkan login atau terjadi error.", "error");
    console.error("❌ Login error:", err);
  }
}