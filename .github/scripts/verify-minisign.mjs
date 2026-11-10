#!/usr/bin/env node
// Prueft eine minisign-Signatur (Format von `tauri signer sign`), ohne Pakete:
// Ed25519 und BLAKE2b-512 kann node:crypto selbst.
//
//   node verify-minisign.mjs <datei> <signatur> <public-key>
//
// <signatur> und <public-key> wie Tauri sie schreibt: base64 der minisign-
// Dateien (.sig bzw. pubkey aus tauri.conf.json), oder die Dateien selbst.
// Exit 0 = gueltig (die Datei ist vom Schluessel signiert, der Kommentar mit
// der globalen Signatur ebenso), sonst Exit 1 mit dem Grund.

import crypto from 'node:crypto'
import fs from 'node:fs'

const [file, sigArg, keyArg] = process.argv.slice(2)
if (!file || !sigArg || !keyArg) {
  console.error('Usage: verify-minisign.mjs <datei> <signatur> <public-key>')
  process.exit(2)
}

const fail = (why) => {
  console.error(`Signatur ungueltig: ${why}`)
  process.exit(1)
}

/** Text einer minisign-Datei: direkt, oder base64 davon (Tauri). */
const minisignText = (arg) => {
  const raw = fs.existsSync(arg) ? fs.readFileSync(arg, 'utf-8').trim() : arg.trim()
  if (raw.startsWith('untrusted comment:')) return raw
  const decoded = Buffer.from(raw, 'base64').toString('utf-8')
  if (!decoded.startsWith('untrusted comment:')) fail('weder minisign-Text noch base64 davon')
  return decoded
}

const keyLines = minisignText(keyArg).split('\n')
const key = Buffer.from(keyLines[1] ?? '', 'base64')
// 2 Bytes Algorithmus "Ed", 8 Bytes Key-ID, 32 Bytes Ed25519-Schluessel.
if (key.length !== 42 || key.subarray(0, 2).toString() !== 'Ed') fail('Public Key hat nicht das minisign-Format')
const keyId = key.subarray(2, 10)
const publicKey = crypto.createPublicKey({
  key: { kty: 'OKP', crv: 'Ed25519', x: key.subarray(10).toString('base64url') },
  format: 'jwk',
})

const sigLines = minisignText(sigArg).split('\n')
const sig = Buffer.from(sigLines[1] ?? '', 'base64')
// 2 Bytes Algorithmus ("Ed" = Datei, "ED" = BLAKE2b-512 der Datei), 8 Bytes Key-ID, 64 Bytes Signatur.
if (sig.length !== 74) fail('Signatur hat nicht das minisign-Format')
const algo = sig.subarray(0, 2).toString()
if (algo !== 'Ed' && algo !== 'ED') fail(`unbekannter Algorithmus ${algo}`)
if (!sig.subarray(2, 10).equals(keyId)) fail('mit einem anderen Schluessel signiert')

const data = fs.readFileSync(file)
const message = algo === 'ED' ? crypto.createHash('blake2b512').update(data).digest() : data
if (!crypto.verify(null, message, publicKey, sig.subarray(10))) fail('passt nicht zur Datei')

// Der vertrauenswuerdige Kommentar ist mit der Signatur zusammen signiert.
const trusted = (sigLines[2] ?? '').replace(/^trusted comment: /, '')
const globalSig = Buffer.from(sigLines[3] ?? '', 'base64')
if (globalSig.length !== 64) fail('globale Signatur fehlt')
if (!crypto.verify(null, Buffer.concat([sig.subarray(10), Buffer.from(trusted)]), publicKey, globalSig)) {
  fail('Kommentar passt nicht zur Signatur')
}
console.log(`Signatur gueltig (${trusted})`)
