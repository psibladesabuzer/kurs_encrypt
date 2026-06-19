const MAGIC = new TextEncoder().encode("KURSMAILENC");
const VERSION = 1;
const TAG_SIZE = 16;
const SALT_SIZE = 16;
const NONCE_SIZE = 12;
const ITERATIONS = 300000;

const fileInput = document.getElementById("fileInput");
const outputName = document.getElementById("outputName");
const password = document.getElementById("password");
const passwordRepeat = document.getElementById("passwordRepeat");
const repeatField = document.getElementById("repeatField");
const showPassword = document.getElementById("showPassword");
const runButton = document.getElementById("runButton");
const statusLine = document.getElementById("status");

document.querySelectorAll("input[name='mode']").forEach((radio) => {
  radio.addEventListener("change", updateMode);
});
fileInput.addEventListener("change", updateOutputName);
showPassword.addEventListener("change", togglePasswordVisibility);
runButton.addEventListener("click", runOperation);

function selectedMode() {
  return document.querySelector("input[name='mode']:checked").value;
}

function updateMode() {
  repeatField.hidden = selectedMode() !== "encrypt";
  updateOutputName();
  setStatus("Файл не выбран.");
}

function updateOutputName() {
  const file = fileInput.files[0];
  if (!file) {
    outputName.value = "";
    outputName.placeholder = "Выберите файл";
    return;
  }

  if (selectedMode() === "encrypt") {
    outputName.value = `${file.name}.aes256`;
    outputName.placeholder = "Имя зашифрованного файла";
    return;
  }

  outputName.value = file.name.endsWith(".aes256")
    ? file.name.slice(0, -".aes256".length)
    : `${file.name}.decrypted`;
  outputName.placeholder = "Имя расшифрованного файла";
}

function togglePasswordVisibility() {
  const type = showPassword.checked ? "text" : "password";
  password.type = type;
  passwordRepeat.type = type;
}

async function runOperation() {
  try {
    validateForm();
    runButton.disabled = true;
    setStatus("Операция выполняется...");

    const file = fileInput.files[0];
    const data = new Uint8Array(await file.arrayBuffer());
    const result = selectedMode() === "encrypt"
      ? await encryptBytes(data, file.name, password.value)
      : await decryptBytes(data, password.value);

    const name = outputName.value || result.name;
    downloadBytes(result.bytes, name);
    setStatus(`Готово: ${name}`, "success");
  } catch (error) {
    setStatus(error.message || String(error), "error");
  } finally {
    runButton.disabled = false;
  }
}

function validateForm() {
  if (!fileInput.files.length) {
    throw new Error("Выберите файл.");
  }
  if (password.value.length < 8) {
    throw new Error("Пароль должен содержать не менее 8 символов.");
  }
  if (selectedMode() === "encrypt" && password.value !== passwordRepeat.value) {
    throw new Error("Пароли не совпадают.");
  }
  if (!outputName.value.trim()) {
    throw new Error("Укажите имя результата.");
  }
}

async function encryptBytes(data, originalName, passwordText) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const key = await deriveKey(passwordText, salt, ITERATIONS);
  const header = buildHeader(originalName, salt, nonce);
  const headerBytes = serializeHeader(header);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: headerBytes, tagLength: TAG_SIZE * 8 },
      key,
      data,
    ),
  );

  const prefix = buildPrefix(headerBytes);
  return {
    name: `${originalName}.aes256`,
    bytes: concatBytes(prefix, encrypted),
  };
}

async function decryptBytes(data, passwordText) {
  const { header, headerBytes, payload } = parseEncryptedFile(data);
  const salt = base64ToBytes(header.salt);
  const nonce = base64ToBytes(header.nonce);
  const key = await deriveKey(passwordText, salt, Number(header.iterations));

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: headerBytes, tagLength: TAG_SIZE * 8 },
      key,
      payload,
    );
    return {
      name: header.original_name || "decrypted_attachment",
      bytes: new Uint8Array(decrypted),
    };
  } catch (error) {
    throw new Error("Не удалось расшифровать файл: неверный пароль или файл поврежден.");
  }
}

async function deriveKey(passwordText, salt, iterations) {
  const passwordBytes = new TextEncoder().encode(passwordText);
  const baseKey = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function buildHeader(originalName, salt, nonce) {
  return {
    algorithm: "AES-256-GCM",
    created_utc: new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00"),
    iterations: ITERATIONS,
    kdf: "PBKDF2-HMAC-SHA256",
    nonce: bytesToBase64(nonce),
    original_name: originalName,
    salt: bytesToBase64(salt),
  };
}

function serializeHeader(header) {
  const orderedKeys = Object.keys(header).sort();
  const parts = orderedKeys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(header[key])}`);
  return new TextEncoder().encode(`{${parts.join(",")}}`);
}

function buildPrefix(headerBytes) {
  const result = new Uint8Array(MAGIC.length + 1 + 4 + headerBytes.length);
  result.set(MAGIC, 0);
  result[MAGIC.length] = VERSION;
  new DataView(result.buffer).setUint32(MAGIC.length + 1, headerBytes.length, false);
  result.set(headerBytes, MAGIC.length + 5);
  return result;
}

function parseEncryptedFile(data) {
  if (data.length < MAGIC.length + 1 + 4 + TAG_SIZE) {
    throw new Error("Файл слишком мал для формата .aes256.");
  }

  for (let index = 0; index < MAGIC.length; index += 1) {
    if (data[index] !== MAGIC[index]) {
      throw new Error("Неподдерживаемый формат файла.");
    }
  }

  if (data[MAGIC.length] !== VERSION) {
    throw new Error("Неподдерживаемая версия файла.");
  }

  const headerLength = new DataView(data.buffer, data.byteOffset + MAGIC.length + 1, 4).getUint32(0, false);
  const headerStart = MAGIC.length + 5;
  const headerEnd = headerStart + headerLength;
  if (headerLength <= 0 || headerEnd >= data.length) {
    throw new Error("Некорректный заголовок файла.");
  }

  const headerBytes = data.slice(headerStart, headerEnd);
  const header = JSON.parse(new TextDecoder().decode(headerBytes));
  validateHeader(header);

  return {
    header,
    headerBytes,
    payload: data.slice(headerEnd),
  };
}

function validateHeader(header) {
  if (header.algorithm !== "AES-256-GCM" || header.kdf !== "PBKDF2-HMAC-SHA256") {
    throw new Error("Неподдерживаемые криптографические параметры.");
  }
  if (Number(header.iterations) < 100000) {
    throw new Error("Недопустимое число итераций PBKDF2.");
  }
  if (base64ToBytes(header.salt).length !== SALT_SIZE || base64ToBytes(header.nonce).length !== NONCE_SIZE) {
    throw new Error("Некорректные параметры salt или nonce.");
  }
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(text) {
  const binary = atob(text);
  const result = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    result[index] = binary.charCodeAt(index);
  }
  return result;
}

function concatBytes(...parts) {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  parts.forEach((part) => {
    result.set(part, offset);
    offset += part.length;
  });
  return result;
}

function downloadBytes(bytes, name) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

function setStatus(message, type = "") {
  statusLine.textContent = message;
  statusLine.className = `status ${type}`.trim();
}

updateMode();
