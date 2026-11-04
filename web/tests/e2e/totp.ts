import { createHmac } from "node:crypto";

function base32(secret: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const bytes = bits.match(/.{8}/g) ?? [];
  return Buffer.from(bytes.map((b) => parseInt(b, 2)));
}

let lastStep = 0;

/** RFC 6238 code. Never reuses a step (the API rejects replays); uses the +1 drift step if needed. */
export function totp(secret: string): string {
  const now = Math.floor(Date.now() / 1000 / 30);
  const step = Math.max(now, lastStep + 1);
  if (step > now + 1) throw new Error("No unused TOTP step available; wait 30s");
  lastStep = step;
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = h[h.length - 1]! & 0xf;
  const code = (h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, "0");
}
