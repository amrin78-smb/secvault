// lib/adapters/sshClient.js
// Shared interactive-shell SSH client for CLI-driven firewall adapters
// (Cisco ASA, Sangfor, ...). CommonJS ONLY — required by adapters that are in
// turn required by services/engine-worker.js (plain node, CommonJS).
//
// FROZEN CONTRACT — the Cisco ASA and Sangfor adapters are both built against
// this exact API. Do not change signatures or option names without updating
// every adapter that consumes this module.
//
// Design notes:
// - Uses a SHELL channel, not an exec channel — many firewall CLIs (ASA
//   included) do not support exec channels, or behave differently on them.
// - Expect-style flow: send a line, accumulate output until the prompt regex
//   matches, capture what came in between.
// - Legacy device compat: older firewall firmware often only offers
//   diffie-hellman-group14-sha1 / group-exchange-sha1 kex, CBC ciphers and
//   ssh-rsa host keys. Those are APPENDED to ssh2's defaults (never replacing
//   them) so modern devices still negotiate modern algorithms first.

'use strict';

const { Client } = require('ssh2');

const DEFAULT_PROMPT_REGEX = /[>#$%]\s*$/m;
const PASSWORD_PROMPT_REGEX = /password[: ]*$/i;
const MORE_PAGER_REGEX = /--\s*More\s*--/i;

// Relaxed algorithm set for legacy firewall firmware. The {append: [...]}
// form adds to ssh2's built-in defaults rather than replacing them.
function legacyCompatAlgorithms() {
  return {
    kex: {
      append: ['diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1'],
    },
    cipher: {
      append: ['aes128-cbc', '3des-cbc'],
    },
    serverHostKey: {
      append: ['ssh-rsa'],
    },
  };
}

// Strip terminal control noise (ANSI escapes, backspaces) and pager markers
// from an accumulated buffer chunk. Purely defensive — with the pager disabled
// via initCommands none of this should appear, but "should" is not "will".
function scrubControlSequences(text) {
  return text
    // ANSI escape sequences (colors, cursor movement)
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    // Pager markers: "--More--", "<--- More --->", " --More-- " etc.
    .replace(/<?-+\s*More\s*-+>?/gi, '')
    // Backspace-erase sequences pagers use to wipe the marker line
    .replace(/[\b\x08]+\s*[\b\x08]*/g, '');
}

// Removes the echoed command from the start of a captured block and the
// trailing prompt line from its end.
function cleanOutput(raw, command, promptRegex) {
  const lines = String(raw).replace(/\r/g, '').split('\n');

  // Strip leading blank lines, then the echoed command line. The echo may be
  // just the command, or prompt+command on one line — handle both.
  while (lines.length > 0 && lines[0].trim() === '') lines.shift();
  if (lines.length > 0) {
    const first = lines[0].trim();
    if (first === command.trim() || first.endsWith(command.trim())) {
      lines.shift();
    }
  }

  // Strip trailing blank lines, then the trailing prompt line.
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop();
  if (lines.length > 0 && promptRegex.test(lines[lines.length - 1])) {
    lines.pop();
  }

  return lines.join('\n').trim();
}

/**
 * Open ONE ssh2 connection + shell channel to `conn`, run `initCommands` then
 * `commands` sequentially expect-style, and return the captured output of
 * each command.
 *
 * @param {{host: string, port?: number, username: string, password: string}} conn
 * @param {string[]} commands
 * @param {{
 *   promptRegex?: RegExp,       // CLI prompt matcher (default /[>#$%]\s*$/m)
 *   initCommands?: string[],    // e.g. pager-off commands; output discarded
 *   commandTimeoutMs?: number,  // per-command / per-prompt-wait timeout
 *   connectTimeoutMs?: number,  // TCP + SSH handshake timeout
 *   enablePassword?: string|null, // if set: enter privileged mode first
 *   windowLine?: number|null,   // pty rows — some CLIs (no pager-off command)
 *                               // paginate by window height; a large value
 *                               // effectively disables their pager
 * }} [options]
 * @returns {Promise<Array<{command: string, output: string}>>}
 */
async function runCommands(conn, commands, options = {}) {
  const {
    promptRegex = DEFAULT_PROMPT_REGEX,
    initCommands = [],
    commandTimeoutMs = 20000,
    connectTimeoutMs = 15000,
    enablePassword = null,
    windowLine = null,
  } = options;

  if (!conn || !conn.host || !conn.username) {
    throw new Error('runCommands: conn must include at least host and username');
  }

  const commandList = Array.isArray(commands) ? commands : [commands];
  const client = new Client();

  try {
    return await new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      };
      const succeed = (value) => {
        if (!settled) {
          settled = true;
          resolve(value);
        }
      };

      client.on('error', (err) => {
        fail(new Error(`SSH connection error to ${conn.host}:${conn.port || 22}: ${err.message}`));
      });

      // Legacy device compat: some firewalls only offer keyboard-interactive
      // auth. Answer every prompt with the password.
      client.on('keyboard-interactive', (name, instructions, instructionsLang, prompts, finish) => {
        finish(prompts.map(() => conn.password || ''));
      });

      client.on('close', () => {
        fail(new Error(`SSH connection to ${conn.host} closed before all commands completed`));
      });

      client.on('ready', () => {
        const ptyOptions = {
          term: 'vt100',
          cols: 512,
          rows: typeof windowLine === 'number' && windowLine > 0 ? windowLine : 500,
        };

        client.shell(ptyOptions, (err, stream) => {
          if (err) {
            return fail(new Error(`Failed to open shell channel on ${conn.host}: ${err.message}`));
          }

          let buffer = '';
          let waiter = null; // { regex, label, resolve, reject, timer }

          const checkWaiter = () => {
            if (waiter && waiter.regex.test(buffer)) {
              clearTimeout(waiter.timer);
              const w = waiter;
              waiter = null;
              w.resolve(buffer);
            }
          };

          const onData = (chunk) => {
            buffer += chunk.toString('utf8');
            // Defensive --More-- pagination handling (belt-and-braces even
            // when the pager was disabled via initCommands): send a space to
            // advance, scrub the marker so it never pollutes output or
            // confuses the prompt regex.
            if (MORE_PAGER_REGEX.test(buffer)) {
              buffer = scrubControlSequences(buffer);
              stream.write(' ');
            }
            checkWaiter();
          };

          stream.on('data', onData);
          stream.stderr.on('data', onData);
          stream.on('close', () => {
            if (waiter) {
              clearTimeout(waiter.timer);
              const w = waiter;
              waiter = null;
              w.reject(new Error(`SSH shell channel closed while waiting for ${w.label}`));
            }
          });

          const waitFor = (regex, label, timeoutMs) =>
            new Promise((res, rej) => {
              if (regex.test(buffer)) return res(buffer);
              waiter = {
                regex,
                label,
                resolve: res,
                reject: rej,
                timer: setTimeout(() => {
                  waiter = null;
                  rej(new Error(`Timed out after ${timeoutMs}ms waiting for ${label} on ${conn.host}`));
                }, timeoutMs),
              };
            });

          const send = (line) => stream.write(line + '\n');

          (async () => {
            // 1. Initial prompt (after banner/MOTD).
            await waitFor(promptRegex, 'initial prompt', commandTimeoutMs);

            // 2. Privileged mode, if requested. Defensive: if the session is
            //    already privileged the device may answer `enable` with a
            //    prompt instead of a password prompt — accept either.
            if (enablePassword) {
              buffer = '';
              send('enable');
              const passwordOrPrompt = new RegExp(
                `(${PASSWORD_PROMPT_REGEX.source})|(${promptRegex.source})`,
                'im'
              );
              const enableResponse = await waitFor(
                passwordOrPrompt,
                'enable password prompt',
                commandTimeoutMs
              );
              if (PASSWORD_PROMPT_REGEX.test(enableResponse)) {
                buffer = '';
                send(enablePassword);
                await waitFor(promptRegex, 'prompt after enable password', commandTimeoutMs);
              }
            }

            // 3. Init commands (e.g. pager off) — output discarded.
            for (const initCmd of initCommands) {
              buffer = '';
              send(initCmd);
              await waitFor(promptRegex, `prompt after init command "${initCmd}"`, commandTimeoutMs);
            }

            // 4. The actual commands, capturing output between send and the
            //    next prompt match.
            const results = [];
            for (const cmd of commandList) {
              buffer = '';
              send(cmd);
              let captured;
              try {
                captured = await waitFor(promptRegex, `output of command "${cmd}"`, commandTimeoutMs);
              } catch (waitErr) {
                throw new Error(`Command "${cmd}" failed on ${conn.host}: ${waitErr.message}`);
              }
              results.push({
                command: cmd,
                output: cleanOutput(scrubControlSequences(captured), cmd, promptRegex),
              });
            }

            return results;
          })().then(succeed, fail);
        });
      });

      client.connect({
        host: conn.host,
        port: conn.port || 22,
        username: conn.username,
        password: conn.password,
        readyTimeout: connectTimeoutMs,
        tryKeyboard: true,
        algorithms: legacyCompatAlgorithms(),
      });
    });
  } finally {
    // ALWAYS end the connection — success, timeout, or error.
    try {
      client.end();
    } catch (endErr) {
      // ignore — best-effort cleanup
    }
  }
}

/**
 * Parse a decrypted credStore SSH credential (stored as a JSON string) into
 * { username, password, enable_password? }.
 *
 * @param {string} plaintext
 * @returns {{username: string, password: string, enable_password?: string}}
 */
function parseJsonCredential(plaintext) {
  let parsed;
  try {
    parsed = JSON.parse(plaintext);
  } catch (err) {
    throw new Error(
      'SSH credential is not valid JSON — expected {"username":"...","password":"...","enable_password":"..."} (enable_password optional)'
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('SSH credential JSON must be an object with "username" and "password" fields');
  }
  if (!parsed.username || !parsed.password) {
    throw new Error('SSH credential JSON is missing required "username" and/or "password" fields');
  }
  return parsed;
}

module.exports = { runCommands, parseJsonCredential };
