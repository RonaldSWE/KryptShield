const siteName = document.getElementById("siteName");
const password = document.getElementById("password");
const submitBtn = document.getElementById("submitBtn");
const elements = document.getElementById("elements");

const masterPassInput = document.getElementById("masterPass");
const unlockBtn = document.getElementById("unlockBtn");
const lockBtn = document.getElementById("lockBtn");
const status = document.getElementById("status");

let cryptoKey = null; // CryptoKey when unlocked
let entries = []; // decrypted entries in memory

// Utility: convert string <-> ArrayBuffer
const enc = new TextEncoder();
const dec = new TextDecoder();

async function deriveKey(password, salt) {
    const pwKey = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 150000,
            hash: "SHA-256",
        },
        pwKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

function randomBytes(len) {
    const a = new Uint8Array(len);
    window.crypto.getRandomValues(a);
    return a;
}

function bufferToB64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++)
        binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function b64ToBuffer(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

async function encryptEntries(key, items) {
    const iv = randomBytes(12);
    const plaintext = enc.encode(JSON.stringify(items));
    const ct = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        plaintext
    );
    return {
        iv: bufferToB64(iv.buffer),
        ct: bufferToB64(ct),
    };
}

async function decryptEntries(key, iv_b64, ct_b64) {
    const iv = b64ToBuffer(iv_b64);
    const ct = b64ToBuffer(ct_b64);
    const pt = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(iv) },
        key,
        ct
    );
    return JSON.parse(dec.decode(pt));
}

function saveEncryptedPackage(salt_b64, iv_b64, ct_b64) {
    const pkg = { salt: salt_b64, iv: iv_b64, ct: ct_b64 };
    localStorage.setItem("encryptedEntries", JSON.stringify(pkg));
}

function loadEncryptedPackage() {
    const raw = localStorage.getItem("encryptedEntries");
    return raw ? JSON.parse(raw) : null;
}

async function setOrUnlock() {
    const master = masterPassInput.value;
    if (!master) {
        alert("Enter a master password");
        return;
    }

    const pkg = loadEncryptedPackage();
    if (!pkg) {
        // No data yet: create salt, derive key, save empty encrypted package
        const salt = randomBytes(16);
        cryptoKey = await deriveKey(master, salt.buffer);
        entries = [];
        const encPkg = await encryptEntries(cryptoKey, entries);
        saveEncryptedPackage(bufferToB64(salt.buffer), encPkg.iv, encPkg.ct);
        status.textContent = "Unlocked (new)";
        lockBtn.disabled = false;
    } else {
        // Try to derive key and decrypt
        try {
            const saltBuf = b64ToBuffer(pkg.salt);
            cryptoKey = await deriveKey(master, saltBuf);
            const decrypted = await decryptEntries(cryptoKey, pkg.iv, pkg.ct);
            entries = decrypted;
            renderEntries(entries);
            status.textContent = "Unlocked";
            lockBtn.disabled = false;
        } catch (e) {
            console.error(e);
            alert("Failed to unlock — master password may be incorrect.");
            cryptoKey = null;
            entries = [];
            renderEntries(entries);
            status.textContent = "Locked";
        }
    }
}

function lock() {
    cryptoKey = null;
    entries = [];
    renderEntries(entries);
    masterPassInput.value = "";
    status.textContent = "Locked";
    lockBtn.disabled = true;
}

async function saveAndEncryptCurrent() {
    if (!cryptoKey) {
        alert("Unlock with your master password first");
        return;
    }
    const encPkg = await encryptEntries(cryptoKey, entries);
    // need salt too — existing package has it
    const pkg = loadEncryptedPackage();
    const salt = pkg ? pkg.salt : bufferToB64(randomBytes(16).buffer);
    saveEncryptedPackage(salt, encPkg.iv, encPkg.ct);
}

unlockBtn.addEventListener("click", setOrUnlock);
lockBtn.addEventListener("click", lock);

submitBtn.addEventListener("click", async function () {
    if (!cryptoKey) {
        alert("Unlock with your master password first");
        return;
    }
    if (siteName.value === "" || password.value === "") {
        alert("Please fill in both fields.❗");
        return;
    }
    const entry = {
        id: Date.now(),
        site: siteName.value,
        password: password.value,
    };
    entries.push(entry);
    await saveAndEncryptCurrent();
    renderEntries(entries);
    siteName.value = "";
    password.value = "";
});

function renderEntries(items) {
    elements.innerHTML = "";
    if (!cryptoKey) return; // don't render if locked
    items.forEach((e) => {
        const li = document.createElement("li");
        li.textContent = `Site: ${e.site} | Password: ${e.password}`;

        const del = document.createElement("button");
        del.textContent = "X";
        del.style.marginLeft = "8px";
        del.style.cursor = "pointer";
        del.style.backgroundColor = "#ff1b1bff";
        del.style.color = "white";
        del.style.borderRadius = "10px";
        del.addEventListener("click", async () => {
            entries = entries.filter((x) => x.id !== e.id);
            await saveAndEncryptCurrent();
            renderEntries(entries);
        });

        li.appendChild(del);
        elements.appendChild(li);
    });
}
