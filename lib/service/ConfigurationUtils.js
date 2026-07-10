"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigurationUtils = void 0;
const fs_1 = require("fs");
const path_1 = require("path");
const symbol_sdk_1 = require("symbol-sdk");
const PqcCrypto_1 = require("./PqcCrypto");
const Constants_1 = require("./Constants");
const YamlUtils_1 = require("./YamlUtils");
/**
 * Utility class for bootstrap configuration related methods.
 */
class ConfigurationUtils {
    static toConfigAccountFomKeys(networkType, publicKey, privateKey) {
        const account = this.toAccount(networkType, publicKey, privateKey);
        if (!account) {
            return undefined;
        }
        return this.toConfigAccount(account);
    }
    // Wraps a plain address string so bootstrap's `.address.plain()` / `.address.equals()` usage keeps working.
    static wrapAddress(addressString) {
        return {
            plain: () => addressString,
            pretty: () => addressString,
            encoded: () => PqcCrypto_1.PqcCrypto.encodedAddress(addressString),
            equals: other => addressString === (other && other.plain ? other.plain() : other),
        };
    }
    // Builds a PQC (ML-DSA-44) account object duck-typed to how bootstrap consumes symbol-sdk accounts.
    static toPqcAccount(privateKey, publicKey, networkByte) {
        const address = PqcCrypto_1.PqcCrypto.addressFromPublicKey(publicKey, networkByte);
        const account = { publicKey: publicKey.toUpperCase(), address: ConfigurationUtils.wrapAddress(address) };
        if (privateKey) {
            account.privateKey = String(privateKey).toUpperCase();
        }
        return account;
    }
    static toAccount(networkType, publicKey, privateKey) {
        // PQC: accounts are ML-DSA-44; addresses are derived from the 1312-byte public key
        const networkByte = networkType & 0xff;
        if (privateKey) {
            const derived = PqcCrypto_1.PqcCrypto.accountFromPrivateKey(privateKey, networkByte);
            if (publicKey && derived.publicKey.toUpperCase() != publicKey.toUpperCase()) {
                throw new Error('Invalid provided public key/private key!');
            }
            return ConfigurationUtils.toPqcAccount(derived.privateKey, derived.publicKey, networkByte);
        }
        if (publicKey) {
            return ConfigurationUtils.toPqcAccount(undefined, publicKey, networkByte);
        }
        return undefined;
    }
    static toConfigAccount(account) {
        const address = typeof account.address === 'string' ? account.address : account.address.plain();
        if (account.privateKey) {
            return { privateKey: account.privateKey, publicKey: account.publicKey, address };
        }
        return { publicKey: account.publicKey, address };
    }
    static resolveRoles(nodePreset) {
        if (nodePreset.roles) {
            return nodePreset.roles;
        }
        const roles = [];
        if (nodePreset.syncsource) {
            roles.push('Peer');
        }
        if (nodePreset.api) {
            roles.push('Api');
        }
        if (nodePreset.voting) {
            roles.push('Voting');
        }
        return roles.join(',');
    }
    static shouldCreateNemesis(presetData) {
        return (presetData.nemesis &&
            !presetData.nemesisSeedFolder &&
            (YamlUtils_1.YamlUtils.isYmlFile(presetData.preset) || !(0, fs_1.existsSync)((0, path_1.join)(Constants_1.Constants.ROOT_FOLDER, 'presets', presetData.preset, 'seed'))));
    }
}
exports.ConfigurationUtils = ConfigurationUtils;
