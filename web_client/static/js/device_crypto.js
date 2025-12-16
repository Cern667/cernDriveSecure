/**
 * Module de gestion des clés d'appareil (Device Keys)
 * Génération Ed25519, signature, stockage IndexedDB
 * 
 * Architecture :
 * - Chaque appareil possède sa propre paire de clés Ed25519
 * - Clé privée stockée dans IndexedDB (ne quitte JAMAIS le navigateur)
 * - Clé publique envoyée au serveur pour autorisation
 * - Signature cryptographique pour autoriser nouveaux appareils
 */

// ============================================================================
// 1. INDEXED DB STORAGE
// ============================================================================

const DB_NAME = 'NAS_DeviceKeys';
const DB_VERSION = 1;
const STORE_NAME = 'device_keys';

/**
 * Initialise la base de données IndexedDB
 * @returns {Promise<IDBDatabase>}
 */
async function initIndexedDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME);
            }
        };
    });
}

/**
 * Stocke une valeur dans IndexedDB
 * @param {string} key - Clé
 * @param {any} value - Valeur
 */
async function storeInIndexedDB(key, value) {
    const db = await initIndexedDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.put(value, key);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}

/**
 * Récupère une valeur depuis IndexedDB
 * @param {string} key - Clé
 * @returns {Promise<any>}
 */
async function getFromIndexedDB(key) {
    const db = await initIndexedDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.get(key);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
    });
}

/**
 * Supprime une valeur d'IndexedDB
 * @param {string} key - Clé
 */
async function deleteFromIndexedDB(key) {
    const db = await initIndexedDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.delete(key);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}

// ============================================================================
// 2. ED25519 KEY GENERATION
// ============================================================================

/**
 * Génère une paire de clés Ed25519 pour l'appareil
 * NOTE: Web Crypto API ne supporte pas Ed25519 nativement partout
 * Fallback sur P-256 si nécessaire
 * 
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
async function generateDeviceKeyPair() {
    try {
        // Tenter Ed25519 (supporté dans Chrome 113+, Firefox 119+)
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "Ed25519"
            },
            true, // extractable
            ["sign", "verify"]
        );

        console.log("✅ Clés appareil Ed25519 générées");
        return keyPair;

    } catch (error) {
        console.warn("⚠️ Ed25519 non supporté, utilisation ECDSA P-256");

        // Fallback sur ECDSA P-256 pour signer
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            true,
            ["sign", "verify"]
        );

        return keyPair;
    }
}

/**
 * Stocke la paire de clés appareil dans IndexedDB
 * @param {CryptoKey} privateKey - Clé privée
 * @param {CryptoKey} publicKey - Clé publique
 */
async function storeDeviceKeys(privateKey, publicKey) {
    // Exporter les clés en format JWK pour stockage
    const privateKeyJWK = await window.crypto.subtle.exportKey("jwk", privateKey);
    const publicKeyJWK = await window.crypto.subtle.exportKey("jwk", publicKey);

    // Stocker
    await storeInIndexedDB('device_private_key', privateKeyJWK);
    await storeInIndexedDB('device_public_key', publicKeyJWK);

    console.log("✅ Clés appareil stockées dans IndexedDB");
}

/**
 * Récupère la clé privée de l'appareil
 * @returns {Promise<CryptoKey|null>}
 */
async function getDevicePrivateKey() {
    const privateKeyJWK = await getFromIndexedDB('device_private_key');

    if (!privateKeyJWK) {
        return null;
    }

    // Déterminer l'algorithme
    const algorithm = privateKeyJWK.crv === "Ed25519"
        ? { name: "Ed25519" }
        : { name: "ECDSA", namedCurve: "P-256" };

    const privateKey = await window.crypto.subtle.importKey(
        "jwk",
        privateKeyJWK,
        algorithm,
        true,
        ["sign"]
    );

    return privateKey;
}

/**
 * Récupère la clé publique de l'appareil
 * @returns {Promise<CryptoKey|null>}
 */
async function getDevicePublicKey() {
    const publicKeyJWK = await getFromIndexedDB('device_public_key');

    if (!publicKeyJWK) {
        return null;
    }

    // Déterminer l'algorithme
    const algorithm = publicKeyJWK.crv === "Ed25519"
        ? { name: "Ed25519" }
        : { name: "ECDSA", namedCurve: "P-256" };

    const publicKey = await window.crypto.subtle.importKey(
        "jwk",
        publicKeyJWK,
        algorithm,
        true,
        ["verify"]
    );

    return publicKey;
}

/**
 * Vérifie si l'appareil possède déjà des clés
 * @returns {Promise<boolean>}
 */
async function hasDeviceKeys() {
    const privateKeyJWK = await getFromIndexedDB('device_private_key');
    return privateKeyJWK !== undefined && privateKeyJWK !== null;
}

// ============================================================================
// 3. SIGNATURE CRYPTOGRAPHIQUE
// ============================================================================

/**
 * Signe un message avec la clé privée de l'appareil
 * @param {string} message - Message à signer
 * @returns {Promise<string>} Signature en base64
 */
async function signWithDeviceKey(message) {
    const privateKey = await getDevicePrivateKey();

    if (!privateKey) {
        throw new Error("Clé privée appareil introuvable");
    }

    // Encoder le message
    const encoder = new TextEncoder();
    const data = encoder.encode(message);

    // Déterminer l'algorithme de signature
    const privateKeyJWK = await getFromIndexedDB('device_private_key');
    const algorithm = privateKeyJWK.crv === "Ed25519"
        ? { name: "Ed25519" }
        : { name: "ECDSA", hash: "SHA-256" };

    // Signer
    const signature = await window.crypto.subtle.sign(
        algorithm,
        privateKey,
        data
    );

    // Convertir en base64
    return CryptoClient.arrayBufferToBase64(signature);
}

/**
 * Exporte la clé publique de l'appareil en base64
 * @returns {Promise<string>}
 */
async function exportDevicePublicKey() {
    const publicKey = await getDevicePublicKey();

    if (!publicKey) {
        throw new Error("Clé publique appareil introuvable");
    }

    // Exporter en format raw pour Ed25519 ou SPKI pour ECDSA
    const publicKeyJWK = await getFromIndexedDB('device_public_key');

    if (publicKeyJWK.crv === "Ed25519") {
        const exported = await window.crypto.subtle.exportKey("raw", publicKey);
        return CryptoClient.arrayBufferToBase64(exported);
    } else {
        // Pour ECDSA, exporter en raw (65 bytes)
        const exported = await window.crypto.subtle.exportKey("raw", publicKey);
        return CryptoClient.arrayBufferToBase64(exported);
    }
}

// ============================================================================
// 4. WORKFLOW AUTHORIZATION
// ============================================================================

/**
 * Crée un message d'autorisation pour signature
 * @param {string} session_id - ID de session
 * @param {string} device_public_key - Clé publique du nouvel appareil
 * @param {number} timestamp - Timestamp Unix
 * @returns {string}
 */
function createAuthorizationMessage(session_id, device_public_key, timestamp) {
    return `AUTHORIZE_DEVICE|${session_id}|${device_public_key}|${timestamp}`;
}

/**
 * Génère une signature d'autorisation pour un nouvel appareil
 * @param {string} session_id - ID de session
 * @param {string} new_device_pubkey - Clé publique du nouvel appareil
 * @param {number} timestamp - Timestamp
 * @returns {Promise<string>} Signature en base64
 */
async function generateAuthorizationSignature(session_id, new_device_pubkey, timestamp) {
    const message = createAuthorizationMessage(session_id, new_device_pubkey, timestamp);
    return await signWithDeviceKey(message);
}

// ============================================================================
// 5. EXPORT MODULE
// ============================================================================

window.DeviceCrypto = {
    // Génération et stockage
    generateDeviceKeyPair,
    storeDeviceKeys,
    hasDeviceKeys,

    // Récupération
    getDevicePrivateKey,
    getDevicePublicKey,
    exportDevicePublicKey,

    // Signature
    signWithDeviceKey,
    createAuthorizationMessage,
    generateAuthorizationSignature,

    // IndexedDB utils
    storeInIndexedDB,
    getFromIndexedDB,
    deleteFromIndexedDB
};

console.log("🔐 Module DeviceCrypto chargé (Ed25519)");
