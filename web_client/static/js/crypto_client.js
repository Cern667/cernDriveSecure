/**
 * Module de chiffrement côté client Zero-Knowledge
 * Architecture inspirée de Proton Drive
 * 
 * Principe :
 * - Clé privée X25519 générée dans le navigateur
 * - Clé privée chiffrée avec le mot de passe utilisateur (PBKDF2)
 * - Clé privée chiffrée stockée sur le serveur (zero-knowledge)
 * - Déchiffrement côté client uniquement
 * 
 * Le serveur ne connaît JAMAIS :
 * - Le mot de passe utilisateur
 * - La clé privée en clair
 * - Le contenu des fichiers en clair
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    PBKDF2_ITERATIONS: 100000,  // Nombre d'itérations pour PBKDF2
    SALT_LENGTH: 32,             // Taille du salt en bytes
    KEY_LENGTH: 32,              // Taille de la clé AES en bytes
    IV_LENGTH: 12,               // Taille de l'IV pour AES-GCM
};

// ============================================================================
// 1. GÉNÉRATION ET GESTION DES CLÉS
// ============================================================================

/**
 * Génère une paire de clés X25519 dans le navigateur
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
async function generateX25519KeyPair() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "X25519", // Équivalent X25519
            },
            true, // extractable
            ["deriveKey", "deriveBits"]
        );

        console.log("✅ Paire de clés X25519 générée");
        return keyPair;
    } catch (error) {
        console.error("❌ Erreur génération clés X25519:", error);

        // Fallback sur P-256 si X25519 n'est pas supporté
        console.warn("⚠️ X25519 non supporté, utilisation de P-256");
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256",
            },
            true,
            ["deriveKey", "deriveBits"]
        );

        return keyPair;
    }
}

/**
 * Dérive une clé de chiffrement depuis un mot de passe
 * @param {string} password - Mot de passe utilisateur
 * @param {Uint8Array} salt - Salt (32 bytes)
 * @returns {Promise<CryptoKey>} Clé AES-GCM dérivée
 */
async function deriveKeyFromPassword(password, salt) {
    // Encoder le mot de passe
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    // Importer le mot de passe comme clé
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    // Dériver une clé AES-GCM avec PBKDF2
    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        baseKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false, // non extractable
        ["encrypt", "decrypt"]
    );

    console.log("✅ Clé dérivée du mot de passe");
    return derivedKey;
}

/**
 * Chiffre la clé privée avec le mot de passe utilisateur
 * @param {CryptoKey} privateKey - Clé privée à chiffrer
 * @param {string} password - Mot de passe utilisateur
 * @returns {Promise<{encryptedKey: ArrayBuffer, salt: Uint8Array, iv: Uint8Array}>}
 */
async function encryptPrivateKeyWithPassword(privateKey, password) {
    // Générer un salt aléatoire
    const salt = window.crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));

    // Générer un IV aléatoire
    const iv = window.crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));

    // Dériver une clé depuis le mot de passe
    const derivedKey = await deriveKeyFromPassword(password, salt);

    // Exporter la clé privée en PKCS8
    const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", privateKey);

    // Chiffrer la clé privée avec AES-GCM
    const encryptedKey = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        derivedKey,
        privateKeyBuffer
    );

    console.log("✅ Clé privée chiffrée avec le mot de passe");
    return { encryptedKey, salt, iv };
}

/**
 * Déchiffre la clé privée avec le mot de passe utilisateur
 * @param {ArrayBuffer} encryptedKey - Clé privée chiffrée
 * @param {Uint8Array} salt - Salt utilisé
 * @param {Uint8Array} iv - IV utilisé
 * @param {string} password - Mot de passe utilisateur
 * @returns {Promise<CryptoKey>} Clé privée déchiffrée
 */
async function decryptPrivateKeyWithPassword(encryptedKey, salt, iv, password) {
    // Dériver la clé depuis le mot de passe
    const derivedKey = await deriveKeyFromPassword(password, salt);

    // Déchiffrer la clé privée
    const privateKeyBuffer = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        derivedKey,
        encryptedKey
    );

    // Importer la clé privée
    const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        privateKeyBuffer,
        {
            name: "ECDH",
            namedCurve: "P-256" // Adapter selon la courbe utilisée
        },
        true,
        ["deriveKey", "deriveBits"]
    );

    console.log("✅ Clé privée déchiffrée");
    return privateKey;
}

// ============================================================================
// 2. CHIFFREMENT/DÉCHIFFREMENT DE FICHIERS
// ============================================================================

/**
 * Chiffre un fichier avec AES-GCM (clé aléatoire)
 * @param {File} file - Fichier à chiffrer
 * @returns {Promise<{encryptedFile: Blob, aesKey: Uint8Array, iv: Uint8Array}>}
 */
async function encryptFile(file) {
    // Générer une clé AES aléatoire
    const aesKey = window.crypto.getRandomValues(new Uint8Array(CONFIG.KEY_LENGTH));

    // Générer un IV aléatoire
    const iv = window.crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));

    // Importer la clé AES
    const cryptoKey = await window.crypto.subtle.importKey(
        "raw",
        aesKey,
        "AES-GCM",
        false,
        ["encrypt"]
    );

    // Lire le fichier
    const fileBuffer = await file.arrayBuffer();

    // Chiffrer le fichier
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        cryptoKey,
        fileBuffer
    );

    // Créer un blob avec IV + données chiffrées
    const encryptedFile = new Blob([iv, new Uint8Array(encryptedBuffer)]);

    console.log(`✅ Fichier chiffré: ${file.name} (${encryptedFile.size} bytes)`);
    return { encryptedFile, aesKey, iv };
}

/**
 * Déchiffre un fichier avec AES-GCM
 * @param {Blob} encryptedBlob - Blob chiffré (IV + données)
 * @param {Uint8Array} aesKey - Clé AES
 * @returns {Promise<Blob>} Fichier déchiffré
 */
async function decryptFile(encryptedBlob, aesKey) {
    // Lire le blob
    const buffer = await encryptedBlob.arrayBuffer();

    // Extraire IV et données chiffrées
    const iv = new Uint8Array(buffer.slice(0, CONFIG.IV_LENGTH));
    const encryptedData = buffer.slice(CONFIG.IV_LENGTH);

    // Importer la clé AES
    const cryptoKey = await window.crypto.subtle.importKey(
        "raw",
        aesKey,
        "AES-GCM",
        false,
        ["decrypt"]
    );

    // Déchiffrer
    const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        cryptoKey,
        encryptedData
    );

    console.log(`✅ Fichier déchiffré (${decryptedBuffer.byteLength} bytes)`);
    return new Blob([decryptedBuffer]);
}

/**
 * Chiffre la clé AES avec la clé publique X25519
 * @param {Uint8Array} aesKey - Clé AES à chiffrer
 * @param {CryptoKey} publicKey - Clé publique du destinataire
 * @returns {Promise<{encryptedAesKey: ArrayBuffer, ephemeralPublicKey: ArrayBuffer}>}
 */
async function encryptAesKeyWithPublicKey(aesKey, publicKey) {
    // Générer une clé éphémère
    const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        ["deriveKey"]
    );

    // Dériver un secret partagé (ECDH)
    const sharedSecret = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey
        },
        ephemeralKeyPair.privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt"]
    );

    // Générer un IV
    const iv = window.crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));

    // Chiffrer la clé AES
    const encryptedAesKey = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        sharedSecret,
        aesKey
    );

    // Exporter la clé publique éphémère
    const ephemeralPublicKey = await window.crypto.subtle.exportKey(
        "raw",
        ephemeralKeyPair.publicKey
    );

    // Combiner : ephemeralPublicKey + iv + encryptedAesKey
    const combined = new Uint8Array(
        ephemeralPublicKey.byteLength + iv.byteLength + encryptedAesKey.byteLength
    );
    combined.set(new Uint8Array(ephemeralPublicKey), 0);
    combined.set(iv, ephemeralPublicKey.byteLength);
    combined.set(new Uint8Array(encryptedAesKey), ephemeralPublicKey.byteLength + iv.byteLength);

    console.log("✅ Clé AES chiffrée avec la clé publique");
    return combined.buffer;
}

/**
 * Déchiffre la clé AES avec la clé privée X25519
 * @param {ArrayBuffer} encryptedData - Données chiffrées (ephemeralPubKey + iv + encryptedAesKey)
 * @param {CryptoKey} privateKey - Clé privée
 * @returns {Promise<Uint8Array>} Clé AES déchiffrée
 */
async function decryptAesKeyWithPrivateKey(encryptedData, privateKey) {
    const data = new Uint8Array(encryptedData);

    // Extraire les composants (P-256 = 65 bytes pour clé publique non compressée)
    const ephemeralPublicKeyBytes = data.slice(0, 65);
    const iv = data.slice(65, 65 + CONFIG.IV_LENGTH);
    const encryptedAesKey = data.slice(65 + CONFIG.IV_LENGTH);

    // Importer la clé publique éphémère
    const ephemeralPublicKey = await window.crypto.subtle.importKey(
        "raw",
        ephemeralPublicKeyBytes,
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        false,
        []
    );

    // Dériver le secret partagé ECDH (bits bruts)
    const sharedSecretBits = await window.crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: ephemeralPublicKey
        },
        privateKey,
        256
    );

    // Appliquer HKDF-SHA256 (comme côté serveur Python)
    const hkdfKey = await window.crypto.subtle.importKey(
        "raw",
        sharedSecretBits,
        "HKDF",
        false,
        ["deriveKey"]
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0), // Pas de salt (comme Python)
            info: new TextEncoder().encode("nas-aes-key-encryption")
        },
        hkdfKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["decrypt"]
    );

    // Déchiffrer la clé AES
    const aesKeyBuffer = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        derivedKey,
        encryptedAesKey
    );

    console.log("✅ Clé AES déchiffrée");
    return new Uint8Array(aesKeyBuffer);
}

// ============================================================================
// 3. UTILITAIRES
// ============================================================================

/**
 * Convertit ArrayBuffer en Base64
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convertit Base64 en ArrayBuffer
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Exporte une clé publique en format PEM
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
async function exportPublicKeyToPEM(publicKey) {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey);
    const exportedAsBase64 = arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
}

/**
 * Exporte une clé publique en format raw (pour envoi au serveur)
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>} Base64
 */
async function exportPublicKeyToBase64(publicKey) {
    const exported = await window.crypto.subtle.exportKey("raw", publicKey);
    return arrayBufferToBase64(exported);
}

// ============================================================================
// 4. EXPORT MODULE
// ============================================================================

window.CryptoClient = {
    // Génération de clés
    generateX25519KeyPair,
    encryptPrivateKeyWithPassword,
    decryptPrivateKeyWithPassword,

    // Chiffrement/Déchiffrement fichiers
    encryptFile,
    decryptFile,
    encryptAesKeyWithPublicKey,
    decryptAesKeyWithPrivateKey,

    // Utilitaires
    arrayBufferToBase64,
    base64ToArrayBuffer,
    exportPublicKeyToPEM,
    exportPublicKeyToBase64,

    // Configuration
    CONFIG
};

console.log("🔐 Module CryptoClient chargé (Zero-Knowledge)");
