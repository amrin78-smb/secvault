const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';

function getKey() {
  const hex = process.env.CREDENTIAL_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('CREDENTIAL_KEY missing or invalid (expected 32-byte hex string)');
  }
  return Buffer.from(hex, 'hex');
}

// Returns { encrypted: 'hex:hex' (ciphertext:authTag), iv: hex }
function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const enc = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: `${enc.toString('hex')}:${tag.toString('hex')}`,
    iv: iv.toString('hex'),
  };
}

function decrypt(encrypted, iv) {
  const key = getKey();
  const [encHex, tagHex] = String(encrypted).split(':');
  if (!encHex || !tagHex) {
    throw new Error('Malformed encrypted credential value');
  }
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const dec = Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]);
  return dec.toString('utf8');
}

// Fetches + decrypts a credential row for a device. Requires `pool` — never omit it.
// credentialType e.g. 'smc_api'
async function getCredential(deviceId, credentialType, pool) {
  if (!pool) throw new Error('getCredential requires pool parameter');
  const result = await pool.query(
    'SELECT encrypted_data, iv FROM device_credentials WHERE device_id = $1 AND credential_type = $2 ORDER BY created_at DESC LIMIT 1',
    [deviceId, credentialType]
  );
  if (result.rows.length === 0) return null;
  const { encrypted_data, iv } = result.rows[0];
  return decrypt(encrypted_data, iv);
}

// Encrypts + upserts (replace) a credential row for a device. Requires `pool`.
//
// ⛔ Changed 2026-07-19, found in a follow-up bug sweep: this used to be a
// DELETE+INSERT inside a transaction on a single checked-out client — atomic
// for a single request, but nothing prevented two CONCURRENT calls for the
// same (device_id, credential_type) from each independently deleting-then-
// inserting and leaving two rows behind (e.g. a double-submitted credential
// rotation). Now that lib/schema.sql's device_credentials table has a
// UNIQUE(device_id, credential_type) constraint (added the same day, with a
// dedupe pass ahead of it), a single INSERT ... ON CONFLICT DO UPDATE is
// both simpler AND genuinely atomic under real concurrency — Postgres
// resolves a conflicting concurrent upsert via row-level locking, not
// application-level DELETE-then-INSERT timing.
async function setCredential(deviceId, credentialType, plaintext, pool) {
  if (!pool) throw new Error('setCredential requires pool parameter');
  const { encrypted, iv } = encrypt(plaintext);
  await pool.query(
    `INSERT INTO device_credentials (device_id, credential_type, encrypted_data, iv, created_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (device_id, credential_type)
     DO UPDATE SET encrypted_data = EXCLUDED.encrypted_data, iv = EXCLUDED.iv, created_at = now()`,
    [deviceId, credentialType, encrypted, iv]
  );
}

module.exports = { encrypt, decrypt, getCredential, setCredential };
