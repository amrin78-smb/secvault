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
// DELETE + INSERT is wrapped in a transaction on a single checked-out client -- doing
// these as two independent pool.query() calls risked leaving a device with NO stored
// credential at all if the connection dropped (or any error occurred) between the
// DELETE succeeding and the INSERT running. That gap only matters against a live pool
// under real network conditions, never in a clean build/test run.
async function setCredential(deviceId, credentialType, plaintext, pool) {
  if (!pool) throw new Error('setCredential requires pool parameter');
  const { encrypted, iv } = encrypt(plaintext);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM device_credentials WHERE device_id = $1 AND credential_type = $2', [
      deviceId,
      credentialType,
    ]);
    await client.query(
      'INSERT INTO device_credentials (device_id, credential_type, encrypted_data, iv) VALUES ($1, $2, $3, $4)',
      [deviceId, credentialType, encrypted, iv]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { encrypt, decrypt, getCredential, setCredential };
