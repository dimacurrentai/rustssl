'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const wasmDir = path.join(__dirname, '..', 'wasm-out');
const wasmJs = path.join(wasmDir, 'rustsslcmd_wasm.js');

if (!fs.existsSync(wasmJs)) {
  process.stderr.write('Error: WASM not built. Run ./wbuild.sh first.\n');
  process.exit(1);
}

const wasm = require(wasmJs);

const args = process.argv.slice(2);
const mode = args[0];
const input = args[1];
const output = args[2];
const password = args[3];

if (!mode || !input || !output) {
  process.stderr.write('Usage: node cli.js enc|dec <input> <output> [password]\n');
  process.exit(1);
}

if (!fs.existsSync(input)) {
  process.stderr.write('Error: input file does not exist: ' + input + '\n');
  process.exit(1);
}

function run(pw) {
  if (mode === 'enc') {
    const plaintext = new Uint8Array(fs.readFileSync(input));
    const seedBuf = crypto.randomBytes(8);
    const seedHi = seedBuf.readUInt32LE(4);
    const seedLo = seedBuf.readUInt32LE(0);
    const result = wasm.encrypt(pw, plaintext, seedHi, seedLo);
    fs.writeFileSync(output, result);
  } else if (mode === 'dec') {
    const data = fs.readFileSync(input, 'utf-8');
    const result = wasm.decrypt(pw, data);
    fs.writeFileSync(output, Buffer.from(result));
  } else {
    process.stderr.write('Unknown mode: ' + mode + '\n');
    process.exit(1);
  }
}

if (password !== undefined) {
  run(password);
} else {
  const rl = readline.createInterface({
    input: fs.createReadStream('/dev/tty'),
    output: process.stderr,
  });
  const prompt = mode === 'enc' ? 'Enter encryption password: ' : 'Enter decryption password: ';
  rl.question(prompt, function (answer) {
    rl.close();
    run(answer);
  });
}
