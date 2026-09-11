/**
 * Bech32 encoding, needed only to mint valid age plugin recipient and identity
 * strings for the mock plugin. Test fixture; not used by hush itself.
 */
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function polymod(values) {
  let chk = 1;
  for (const v of values) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; }
  return chk;
}
function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}
function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1;
  for (const value of data) { acc = (acc << from) | value; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } }
  if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}
function encode(hrp, bytes) {
  const data = convertBits([...bytes], 8, 5, true);
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = polymod(values) ^ 1;
  const chk = []; for (let i = 0; i < 6; i++) chk.push((mod >> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...chk].map((d) => CHARSET[d]).join("");
}
module.exports = { encode };
