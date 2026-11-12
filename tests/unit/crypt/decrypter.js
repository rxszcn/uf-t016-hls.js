import { expect } from 'chai';
import Decrypter from '../../../src/crypt/decrypter';

describe('Decrypter', function () {
  it('decripts correctly aes-128-cbc software mode', function () {
    const data = get128cbcData();

    const config = { enableSoftwareAES: true };
    const decrypter = new Decrypter(config);
    const cbcMode = 0;

    decrypter.softwareDecrypt(data.encrypted, data.key, data.iv, cbcMode);
    const decrypted = decrypter.flush();
    expect(new Uint8Array(decrypted)).to.deep.equal(data.expected);
  });

  it('decripts correctly aes-128-cbc webCrypto mode', async function () {
    const data = get128cbcData();

    const config = { enableSoftwareAES: false };
    const decrypter = new Decrypter(config);
    const cbcMode = 0;
    const decrypted = await decrypter.webCryptoDecrypt(
      data.encrypted,
      data.key,
      data.iv,
      cbcMode,
    );
    expect(new Uint8Array(decrypted)).to.deep.equal(data.expected);
  });

  it('decripts correctly aes-128-cbc', async function () {
    const data = get128cbcData();

    const config = { enableSoftwareAES: true };
    const decrypter = new Decrypter(config);
    const cbcMode = 0;
    const decrypted = await decrypter.decrypt(
      data.encrypted,
      data.key,
      data.iv,
      cbcMode,
    );
    expect(new Uint8Array(decrypted)).to.deep.equal(data.expected);
  });

  it('decripts correctly aes-256-cbc', async function () {
    const data = get256cbcData();

    const config = { enableSoftwareAES: false };
    const decrypter = new Decrypter(config);
    const cbcMode = 0;
    const decrypted = await decrypter.decrypt(
      data.encrypted,
      data.key,
      data.iv,
      cbcMode,
    );
    expect(new Uint8Array(decrypted)).to.deep.equal(data.expected);
  });

  it('decripts correctly aes-256-ctr', async function () {
    const data = get256ctrData();

    const config = { enableSoftwareAES: false };
    const decrypter = new Decrypter(config);
    const ctrMode = 1;
    const decrypted = await decrypter.decrypt(
      data.encrypted,
      data.key,
      data.iv,
      ctrMode,
    );
    expect(new Uint8Array(decrypted)).to.deep.equal(data.expected);
  });
});

describe('Decrypter progressive (chunk boundary) decryption', function () {
  const cbcMode = 0;

  // Feeds ciphertext to the decrypter the way the transmuxer does in
  // progressive loading mode: state is reset on the first chunk of a segment,
  // each chunk goes through decryptChunk(), and flush() drains the tail
  function decryptInChunks(encrypted, key, iv, chunkSizes) {
    const decrypter = new Decrypter({ enableSoftwareAES: true });
    const parts = [];
    let offset = 0;
    let chunkCount = 0;
    while (offset < encrypted.byteLength) {
      const size = Math.min(
        chunkSizes[chunkCount % chunkSizes.length],
        encrypted.byteLength - offset,
      );
      // slice() copies, matching the per-chunk ArrayBuffers delivered by the loader
      const chunk = encrypted.slice(offset, offset + size);
      offset += size;
      chunkCount++;
      if (chunkCount === 1) {
        decrypter.reset();
      }
      const decryptedChunk = decrypter.decryptChunk(chunk, key, iv, cbcMode);
      if (decryptedChunk) {
        parts.push(new Uint8Array(decryptedChunk));
      }
    }
    const tail = decrypter.flush();
    if (tail) {
      parts.push(tail);
    }
    const joined = new Uint8Array(
      parts.reduce((total, part) => total + part.byteLength, 0),
    );
    let joinedOffset = 0;
    parts.forEach((part) => {
      joined.set(part, joinedOffset);
      joinedOffset += part.byteLength;
    });
    return joined;
  }

  it('decrypts aes-128-cbc progressively in 16-byte aligned chunks', function () {
    const data = getMultiBlockCbcData();
    const decrypted = decryptInChunks(data.encrypted, data.key, data.iv, [16]);
    expect(decrypted).to.deep.equal(data.expected);
  });

  it('decrypts aes-128-cbc progressively across unaligned chunk boundaries', function () {
    const data = getMultiBlockCbcData();
    // chunk boundaries not aligned to the 16-byte AES block size
    const decrypted = decryptInChunks(
      data.encrypted,
      data.key,
      data.iv,
      [7, 33, 16, 56],
    );
    expect(decrypted).to.deep.equal(data.expected);
  });

  it('staggers output and emits a single-chunk segment on flush', function () {
    const data = getMultiBlockCbcData();
    const decrypter = new Decrypter({ enableSoftwareAES: true });
    decrypter.reset();
    // the first (and only) chunk returns null: output is staggered by one chunk
    const staggered = decrypter.decryptChunk(
      data.encrypted,
      data.key,
      data.iv,
      cbcMode,
    );
    expect(staggered).to.equal(null);
    const tail = decrypter.flush();
    expect(new Uint8Array(tail)).to.deep.equal(data.expected);
  });

  it('does not strip padding from intermediate chunks', function () {
    const data = getPaddingLookAlikeCbcData();
    // the plaintext of the first 32-byte chunk ends with 0x02, which looks
    // like PKCS7 padding but must not be stripped mid-stream
    const decrypted = decryptInChunks(data.encrypted, data.key, data.iv, [32]);
    expect(decrypted).to.deep.equal(data.expected);
  });

  it('matches one-shot decryption (CBC state chained across chunks)', function () {
    const data = getMultiBlockCbcData();
    const oneShot = new Decrypter({ enableSoftwareAES: true });
    oneShot.softwareDecrypt(data.encrypted, data.key, data.iv, cbcMode);
    const oneShotResult = oneShot.flush();
    const decrypted = decryptInChunks(
      data.encrypted,
      data.key,
      data.iv,
      [65536, 1000, 17],
    );
    expect(decrypted).to.deep.equal(new Uint8Array(oneShotResult));
    expect(decrypted).to.deep.equal(data.expected);
  });
});

function get128cbcData() {
  const key = new Uint8Array([
    0xe5, 0xe9, 0xfa, 0x1b, 0xa3, 0x1e, 0xcd, 0x1a, 0xe8, 0x4f, 0x75, 0xca,
    0xaa, 0x47, 0x4f, 0x3a,
  ]).buffer;
  const iv = new Uint8Array([
    0x66, 0x3f, 0x05, 0xf4, 0x12, 0x02, 0x8f, 0x81, 0xda, 0x65, 0xd2, 0x6e,
    0xe5, 0x64, 0x24, 0xb2,
  ]).buffer;
  const encrypted = new Uint8Array([
    0x2c, 0x94, 0xcf, 0xc0, 0x91, 0xff, 0x0e, 0xcc, 0x98, 0x66, 0xcc, 0x83,
    0x0d, 0xd7, 0xc3, 0x55,
  ]);
  const expected = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x0a]);
  return { key: key, iv: iv, encrypted: encrypted, expected: expected };
}

function get256Data() {
  const key = new Uint8Array([
    0xe5, 0xe9, 0xfa, 0x1b, 0xa3, 0x1e, 0xcd, 0x1a, 0xe8, 0x4f, 0x75, 0xca,
    0xaa, 0x47, 0x4f, 0x3a, 0x66, 0x3f, 0x05, 0xf4, 0x12, 0x02, 0x8f, 0x81,
    0xda, 0x65, 0xd2, 0x6e, 0xe5, 0x64, 0x24, 0xb2,
  ]).buffer;
  const iv = new Uint8Array([
    0xf4, 0x8c, 0xef, 0xa0, 0xad, 0x59, 0xc9, 0xa5, 0x60, 0x16, 0xcf, 0xbb,
    0x26, 0x5b, 0xee, 0x8c,
  ]).buffer;
  const expected = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x0a]);
  return { key: key, iv: iv, expected: expected };
}

function get256cbcData() {
  const some256data = get256Data();
  const encrypted = new Uint8Array([
    0xe7, 0x25, 0x6a, 0x77, 0x3a, 0xa5, 0x43, 0x59, 0xaf, 0x60, 0xc1, 0xd3,
    0xed, 0x31, 0xc4, 0x01,
  ]);
  some256data.encrypted = encrypted;
  return some256data;
}

function get256ctrData() {
  const some256data = get256Data();
  const encrypted = new Uint8Array([0xb8, 0xd1, 0xcf, 0x15, 0x0d, 0x34, 0x12]);
  some256data.encrypted = encrypted;
  return some256data;
}

// Multi-block aes-128-cbc vector: 100 bytes of plaintext (not a multiple of
// the 16-byte block size, so PKCS7 padding ends mid-block), 112 bytes encrypted
function getMultiBlockCbcData() {
  const cbcData = get128cbcData();
  const encrypted = new Uint8Array([
    0xfc, 0xa5, 0x1c, 0x68, 0x04, 0xfa, 0xd2, 0x3b, 0xd1, 0xaf, 0xb9, 0xcf,
    0x2a, 0x45, 0xeb, 0xf5, 0xcc, 0xf4, 0x80, 0xcb, 0x48, 0xf4, 0x32, 0xa5,
    0x7d, 0xd8, 0x45, 0xe8, 0xc5, 0xe2, 0xab, 0xc2, 0xbb, 0xc3, 0x97, 0x63,
    0x83, 0x31, 0x03, 0xb7, 0x11, 0x2e, 0x27, 0xa4, 0x3c, 0x0d, 0x19, 0xe0,
    0x30, 0x86, 0x96, 0x60, 0x82, 0xd4, 0x71, 0x87, 0xad, 0xd5, 0x05, 0x92,
    0xba, 0x98, 0x84, 0x99, 0xf3, 0x5c, 0x47, 0x65, 0x0b, 0x6b, 0xb1, 0x7c,
    0x70, 0x06, 0x0c, 0x51, 0xb6, 0x4b, 0xc1, 0xa2, 0x97, 0x47, 0xc0, 0xde,
    0x0b, 0xeb, 0x3c, 0xb1, 0xb5, 0x14, 0x42, 0xea, 0xc6, 0xe1, 0x8f, 0x15,
    0x32, 0xbe, 0xf0, 0x58, 0x5a, 0x69, 0xaf, 0x8b, 0x75, 0x55, 0xde, 0x22,
    0xbb, 0xc1, 0x2e, 0xf4,
  ]);
  const expected = new Uint8Array([
    0x07, 0x26, 0x45, 0x64, 0x83, 0xa2, 0xc1, 0xe0, 0xff, 0x1e, 0x3d, 0x5c,
    0x7b, 0x9a, 0xb9, 0xd8, 0xf7, 0x16, 0x35, 0x54, 0x73, 0x92, 0xb1, 0xd0,
    0xef, 0x0e, 0x2d, 0x4c, 0x6b, 0x8a, 0xa9, 0xc8, 0xe7, 0x06, 0x25, 0x44,
    0x63, 0x82, 0xa1, 0xc0, 0xdf, 0xfe, 0x1d, 0x3c, 0x5b, 0x7a, 0x99, 0xb8,
    0xd7, 0xf6, 0x15, 0x34, 0x53, 0x72, 0x91, 0xb0, 0xcf, 0xee, 0x0d, 0x2c,
    0x4b, 0x6a, 0x89, 0xa8, 0xc7, 0xe6, 0x05, 0x24, 0x43, 0x62, 0x81, 0xa0,
    0xbf, 0xde, 0xfd, 0x1c, 0x3b, 0x5a, 0x79, 0x98, 0xb7, 0xd6, 0xf5, 0x14,
    0x33, 0x52, 0x71, 0x90, 0xaf, 0xce, 0xed, 0x0c, 0x2b, 0x4a, 0x69, 0x88,
    0xa7, 0xc6, 0xe5, 0x04,
  ]);
  return { key: cbcData.key, iv: cbcData.iv, encrypted, expected };
}

// aes-128-cbc vector whose plaintext ends a mid-stream 32-byte chunk with 0x02,
// which looks like PKCS7 padding but must not be stripped before flush()
function getPaddingLookAlikeCbcData() {
  const cbcData = get128cbcData();
  const encrypted = new Uint8Array([
    0xfc, 0xa5, 0x1c, 0x68, 0x04, 0xfa, 0xd2, 0x3b, 0xd1, 0xaf, 0xb9, 0xcf,
    0x2a, 0x45, 0xeb, 0xf5, 0xe5, 0x48, 0xba, 0x0d, 0x81, 0xc1, 0xfc, 0xae,
    0xc8, 0xf4, 0x56, 0xa3, 0xdd, 0x50, 0x9b, 0x22, 0x37, 0xef, 0xd8, 0x5d,
    0x4f, 0xbf, 0x17, 0x15, 0x10, 0x5e, 0x87, 0x99, 0x4a, 0xfa, 0x09, 0x9b,
    0x72, 0x82, 0x9a, 0xaa, 0x3f, 0xb1, 0xed, 0x0e, 0x64, 0x66, 0x51, 0x0e,
    0x0f, 0x62, 0x2f, 0x70, 0x12, 0x50, 0xd8, 0x97, 0xc7, 0x23, 0x31, 0x72,
    0x6b, 0x31, 0xc9, 0x65, 0x31, 0x34, 0x0a, 0x4a,
  ]);
  const expected = new Uint8Array([
    0x07, 0x26, 0x45, 0x64, 0x83, 0xa2, 0xc1, 0xe0, 0xff, 0x1e, 0x3d, 0x5c,
    0x7b, 0x9a, 0xb9, 0xd8, 0xf7, 0x16, 0x35, 0x54, 0x73, 0x92, 0xb1, 0xd0,
    0xef, 0x0e, 0x2d, 0x4c, 0x6b, 0x8a, 0xa9, 0x02, 0xe7, 0x06, 0x25, 0x44,
    0x63, 0x82, 0xa1, 0xc0, 0xdf, 0xfe, 0x1d, 0x3c, 0x5b, 0x7a, 0x99, 0xb8,
    0xd7, 0xf6, 0x15, 0x34, 0x53, 0x72, 0x91, 0xb0, 0xcf, 0xee, 0x0d, 0x2c,
    0x4b, 0x6a, 0x89, 0xa8,
  ]);
  return { key: cbcData.key, iv: cbcData.iv, encrypted, expected };
}
