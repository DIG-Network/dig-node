// Tiny QR helper for the connect-to-Sage flow (#34): render a `wc:` pairing URI as a
// scannable SVG so the user can scan it into Sage on another device (the copyable
// text is the same-device path). Wraps the battle-tested `qrcode-generator` (MIT) so
// the crate stays offline — the encoder is bundled into wc-bundle.js, no runtime CDN.

import qrcode from "qrcode-generator";

/**
 * Render `text` as a crisp black-on-white QR SVG string sized to `size` px. Uses
 * error-correction level "M" and auto type-number (0 = pick the smallest that fits),
 * which comfortably holds a WalletConnect `wc:` URI. Returns an `<svg>…</svg>` string
 * the page injects via innerHTML.
 */
export function qrSvg(text, size = 220) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount();
  const cell = size / count;
  let rects = "";
  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (qr.isDark(r, c)) {
        const x = (c * cell).toFixed(2);
        const y = (r * cell).toFixed(2);
        const w = cell.toFixed(2);
        rects += `<rect x="${x}" y="${y}" width="${w}" height="${w}" fill="#000"/>`;
      }
    }
  }
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" ` +
    `viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">` +
    `<rect width="${size}" height="${size}" fill="#fff"/>${rects}</svg>`
  );
}
