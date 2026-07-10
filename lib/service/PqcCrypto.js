'use strict';
// PQC crypto / transaction helpers for symbol-bootstrap.
// Replaces the specific ed25519 symbol-sdk 2.x operations (key generation, address derivation,
// vrf public key, KeyLink transaction signing, voting keys) with ML-DSA-44 + iVRF equivalents,
// so the standard bootstrap commands (config / compose / run / link) produce PQC-valid artifacts.
// The @noble PQC/hash libraries are ESM, so they are loaded lazily via dynamic import.
Object.defineProperty(exports, '__esModule', { value: true });
exports.PqcCrypto = void 0;

const crypto = require('crypto');
const { ml_dsa44 } = require('@noble/post-quantum/ml-dsa.js');
const { sha3_256 } = require('@noble/hashes/sha3');
const { ripemd160 } = require('@noble/hashes/ripemd160');

const SIG = 2420;
const KEY = 1312;
const HDR = 4 + 4 + SIG + KEY + 4; // Size + reserved1 + Signature + SignerPublicKey + reserved2
const IVRF_DEFAULT_DEPTH = 16;

const TX_TYPE = {
	VRF_KEY_LINK: 0x4243,
	ACCOUNT_KEY_LINK: 0x414c,
	VOTING_KEY_LINK: 0x4143
};

const hex2b = h => Uint8Array.from(Buffer.from(String(h).replace(/^0x/i, ''), 'hex'));
const b2hex = b => Buffer.from(b).toString('hex').toUpperCase();

const concat = (...arrays) => {
	const total = arrays.reduce((n, a) => n + a.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const a of arrays) { out.set(a, off); off += a.length; }
	return out;
};

const le64 = value => {
	const b = new Uint8Array(8);
	new DataView(b.buffer).setBigUint64(0, BigInt(value), true);
	return b;
};

// RFC 4648 base32 (Symbol variant): a 24-byte address encodes to a 39-character string.
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const base32Encode = bytes => {
	let bits = 0;
	let value = 0;
	let output = '';
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0)
		output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
	return output;
};

const base32Decode = str => {
	let bits = 0;
	let value = 0;
	const out = [];
	for (const ch of str) {
		const idx = BASE32_ALPHABET.indexOf(ch);
		if (idx < 0) continue;
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	return Uint8Array.from(out);
};


class PqcCrypto {
	// --- accounts ---

	/// Derives the 1312-byte ML-DSA-44 public key (hex) from a 32-byte private key/seed (hex).
	static publicKeyFromPrivateKey(privateKeyHex) {
		return b2hex(ml_dsa44.keygen(hex2b(privateKeyHex)).publicKey);
	}

	/// Derives a Symbol address (plain string) from an ML-DSA public key (hex) and network byte.
	static addressFromPublicKey(publicKeyHex, networkByte) {
		const ripe = ripemd160(sha3_256(hex2b(publicKeyHex))); // 20 bytes
		const part = new Uint8Array(21);
		part[0] = networkByte;
		part.set(ripe, 1);
		const checksum = sha3_256(part).subarray(0, 3);
		return base32Encode(concat(part, checksum));
	}

	/// Returns the 24-byte address (uppercase hex) for a plain (base32) address string.
	static encodedAddress(plainAddress) {
		return b2hex(base32Decode(plainAddress));
	}

	/// Builds { privateKey, publicKey, address } from a private key (hex).
	static accountFromPrivateKey(privateKeyHex, networkByte) {
		const publicKey = PqcCrypto.publicKeyFromPrivateKey(privateKeyHex);
		const address = PqcCrypto.addressFromPublicKey(publicKey, networkByte);
		return { privateKey: String(privateKeyHex).toUpperCase(), publicKey, address };
	}

	/// Generates a fresh ML-DSA account { privateKey, publicKey, address }.
	static generateNewAccount(networkByte) {
		return PqcCrypto.accountFromPrivateKey(b2hex(crypto.randomBytes(32)), networkByte);
	}

	/// Deterministically derives a distinct 32-byte vrf seed (hex) from a signer private key (hex).
	static deriveVrfSeed(privateKeyHex) {
		return b2hex(sha3_256(concat(Buffer.from('nemesis-vrf-seed'), hex2b(privateKeyHex))).subarray(0, 32));
	}

	// --- iVRF ---

	/// Computes the registrable iVRF Merkle root (hex) for a vrf private key (hex).
	static iVrfRootFromPrivateKey(vrfPrivateKeyHex, depth = IVRF_DEFAULT_DEPTH) {
		const seed = hex2b(vrfPrivateKeyHex);
		const label = Buffer.from('catapult-ivrf-leaf');
		const leafCount = 2 ** depth;
		let level = new Array(leafCount);
		for (let i = 0; i < leafCount; ++i)
			level[i] = sha3_256(concat(label, seed, le64(i)));
		for (let d = 0; d < depth; ++d) {
			const up = new Array(level.length / 2);
			for (let i = 0; i < level.length; i += 2)
				up[i / 2] = sha3_256(concat(level[i], level[i + 1]));
			level = up;
		}
		return b2hex(level[0]);
	}

	// --- transactions (ML-DSA-44 signed, PQC wire format) ---

	static _signTransaction(signerPrivateKeyHex, type, networkByte, body, generationHashSeedHex, deadline, maxFee) {
		const keyPair = ml_dsa44.keygen(hex2b(signerPrivateKeyHex));
		const total = HDR + 1 + 1 + 2 + 8 + 8 + body.length;
		const buffer = new Uint8Array(total);
		const view = new DataView(buffer.buffer);
		let o = 0;
		view.setUint32(o, total, true); o += 4; // Size
		o += 4; // reserved1
		o += SIG; // Signature (filled after signing)
		buffer.set(keyPair.publicKey, o); o += KEY; // SignerPublicKey
		o += 4; // reserved2
		buffer[o++] = 1; // version
		buffer[o++] = networkByte & 0xff; // network
		view.setUint16(o, type, true); o += 2; // type
		view.setBigUint64(o, BigInt(maxFee), true); o += 8; // maxFee
		view.setBigUint64(o, BigInt(deadline), true); o += 8; // deadline
		buffer.set(body, o);

		const message = concat(hex2b(generationHashSeedHex), buffer.subarray(HDR));
		buffer.set(ml_dsa44.sign(keyPair.secretKey, message), 8);
		return b2hex(buffer);
	}

	/// Signed VrfKeyLink registering an iVRF root (hex payload).
	static signVrfKeyLink(signerPrivateKeyHex, iVrfRootHex, networkByte, generationHashSeedHex, linkAction = 1, deadline = 1, maxFee = 0) {
		const body = concat(hex2b(iVrfRootHex), Uint8Array.of(linkAction));
		return PqcCrypto._signTransaction(signerPrivateKeyHex, TX_TYPE.VRF_KEY_LINK, networkByte, body, generationHashSeedHex, deadline, maxFee);
	}

	/// Signed AccountKeyLink linking a remote (ML-DSA) public key (hex payload).
	static signAccountKeyLink(signerPrivateKeyHex, remotePublicKeyHex, networkByte, generationHashSeedHex, linkAction = 1, deadline = 1, maxFee = 0) {
		const body = concat(hex2b(remotePublicKeyHex), Uint8Array.of(linkAction));
		return PqcCrypto._signTransaction(signerPrivateKeyHex, TX_TYPE.ACCOUNT_KEY_LINK, networkByte, body, generationHashSeedHex, deadline, maxFee);
	}

	/// Signed VotingKeyLink registering an ML-DSA voting public key over [startEpoch, endEpoch] (hex payload).
	static signVotingKeyLink(signerPrivateKeyHex, votingPublicKeyHex, startEpoch, endEpoch, networkByte, generationHashSeedHex, linkAction = 1, deadline = 1, maxFee = 0) {
		const epochs = new Uint8Array(8);
		const dv = new DataView(epochs.buffer);
		dv.setUint32(0, Number(startEpoch), true);
		dv.setUint32(4, Number(endEpoch), true);
		const body = concat(hex2b(votingPublicKeyHex), epochs, Uint8Array.of(linkAction));
		return PqcCrypto._signTransaction(signerPrivateKeyHex, TX_TYPE.VOTING_KEY_LINK, networkByte, body, generationHashSeedHex, deadline, maxFee);
	}

	// --- voting key tree (ML-DSA-44 Bellare-Miner tree, matches crypto_voting/BmPrivateKeyTree) ---

	/// Generates the serialized voting key tree file for [startEpoch, endEpoch] from a root private key (hex).
	static generateVotingKeyFile(rootPrivateKeyHex, startEpoch, endEpoch) {
		const rootKeyPair = ml_dsa44.keygen(hex2b(rootPrivateKeyHex));

		const LEVEL_HEADER_OFFSET = 32;
		const HEADER_SIZE = LEVEL_HEADER_OFFSET + KEY + 16;
		const ENTRY_SIZE = 32 + SIG; // child private key (seed) + signature
		const numEpochs = Number(BigInt(endEpoch) - BigInt(startEpoch) + 1n);
		const buffer = new Uint8Array(HEADER_SIZE + ENTRY_SIZE * numEpochs);
		const view = new DataView(buffer.buffer);

		view.setBigUint64(0, BigInt(startEpoch), true);
		view.setBigUint64(8, BigInt(endEpoch), true);
		view.setBigUint64(16, 0xffffffffffffffffn, true);
		view.setBigUint64(24, 0xffffffffffffffffn, true);
		buffer.set(rootKeyPair.publicKey, LEVEL_HEADER_OFFSET);
		view.setBigUint64(LEVEL_HEADER_OFFSET + KEY, BigInt(startEpoch), true);
		view.setBigUint64(LEVEL_HEADER_OFFSET + KEY + 8, BigInt(endEpoch), true);

		for (let i = 0; i < numEpochs; ++i) {
			const identifier = BigInt(endEpoch) - BigInt(i);
			const childPrivate = crypto.randomBytes(32);
			const childKeyPair = ml_dsa44.keygen(new Uint8Array(childPrivate));
			const signedPayload = concat(childKeyPair.publicKey, le64(identifier));
			const signature = ml_dsa44.sign(rootKeyPair.secretKey, signedPayload);

			const offset = HEADER_SIZE + ENTRY_SIZE * i;
			buffer.set(new Uint8Array(childPrivate), offset);
			buffer.set(signature, offset + 32);
		}
		return { data: Buffer.from(buffer), rootPublicKey: b2hex(rootKeyPair.publicKey) };
	}
}

exports.PqcCrypto = PqcCrypto;
