/**
 * Module de génération d'empreinte d'appareil (Device Fingerprinting)
 * Génère une empreinte unique basée sur les caractéristiques du navigateur et de l'appareil
 */

function generateDeviceFingerprint() {
    // Collecter les informations du navigateur
    const userAgent = navigator.userAgent || '';
    const language = navigator.language || navigator.userLanguage || '';
    const platform = navigator.platform || '';
    const vendor = navigator.vendor || '';

    // Informations d'écran
    const screenWidth = screen.width || 0;
    const screenHeight = screen.height || 0;
    const colorDepth = screen.colorDepth || 0;
    const pixelRatio = window.devicePixelRatio || 1;

    // Fuseau horaire
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    const timezoneOffset = new Date().getTimezoneOffset();

    // Canvas fingerprinting (empreinte graphique)
    let canvasFingerprint = '';
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('NAS Device ID', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('NAS Device ID', 4, 17);
        canvasFingerprint = canvas.toDataURL().substring(0, 100);
    } catch (e) {
        canvasFingerprint = 'unsupported';
    }

    // WebGL fingerprinting
    let webglFingerprint = '';
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                webglFingerprint = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            }
        }
    } catch (e) {
        webglFingerprint = 'unsupported';
    }

    // Plugins (limité pour la compatibilité)
    let pluginsHash = '';
    try {
        const plugins = Array.from(navigator.plugins || [])
            .map(p => p.name)
            .sort()
            .join(',');
        pluginsHash = plugins.substring(0, 50);
    } catch (e) {
        pluginsHash = 'unsupported';
    }

    // Combiner toutes les données
    const fingerprintData = {
        userAgent,
        language,
        platform,
        vendor,
        screenInfo: `${screenWidth}x${screenHeight}x${colorDepth}@${pixelRatio}`,
        timezone,
        timezoneOffset,
        canvasFingerprint,
        webglFingerprint,
        pluginsHash,
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
        maxTouchPoints: navigator.maxTouchPoints || 0
    };

    // Créer une chaîne unique
    const fingerprintString = JSON.stringify(fingerprintData);

    // Calculer un hash SHA-256 (simulation simple)
    return simpleHash(fingerprintString);
}

/**
 * Fonction de hachage simple (pour démo)
 * En production, utiliser crypto.subtle.digest('SHA-256', ...)
 */
function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }
    // Convertir en hexa et rallonger
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    // Simuler un hash plus long
    return hex.repeat(8).substring(0, 64);
}

/**
 * Fonction asynchrone pour générer un hash SHA-256 réel
 */
async function generateSecureFingerprint() {
    const userAgent = navigator.userAgent || '';
    const language = navigator.language || navigator.userLanguage || '';
    const screenInfo = `${screen.width}x${screen.height}x${screen.colorDepth}`;

    const fingerprintData = {
        userAgent,
        language,
        screenInfo,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
        platform: navigator.platform || '',
        hardwareConcurrency: navigator.hardwareConcurrency || 0
    };

    const fingerprintString = JSON.stringify(fingerprintData);

    // Utiliser l'API Crypto si disponible
    if (window.crypto && window.crypto.subtle) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(fingerprintString);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return hashHex;
        } catch (e) {
            console.warn('Crypto API not available, using fallback');
            return simpleHash(fingerprintString);
        }
    } else {
        return simpleHash(fingerprintString);
    }
}

/**
 * Obtenir des informations lisibles sur l'appareil
 */
function getDeviceInfo() {
    const ua = navigator.userAgent;
    let deviceName = 'Unknown Device';

    // Détecter le type d'appareil
    if (/mobile/i.test(ua)) {
        deviceName = 'Mobile Device';
        if (/iPhone/i.test(ua)) deviceName = 'iPhone';
        else if (/iPad/i.test(ua)) deviceName = 'iPad';
        else if (/Android/i.test(ua)) deviceName = 'Android Device';
    } else if (/tablet/i.test(ua)) {
        deviceName = 'Tablet';
    } else {
        deviceName = 'Desktop Computer';
        if (/Windows/i.test(ua)) deviceName = 'Windows PC';
        else if (/Mac/i.test(ua)) deviceName = 'Mac';
        else if (/Linux/i.test(ua)) deviceName = 'Linux PC';
    }

    // Ajouter le navigateur
    let browser = '';
    if (/Chrome/i.test(ua)) browser = 'Chrome';
    else if (/Firefox/i.test(ua)) browser = 'Firefox';
    else if (/Safari/i.test(ua)) browser = 'Safari';
    else if (/Edge/i.test(ua)) browser = 'Edge';
    else browser = 'Other';

    return {
        device_name: `${deviceName} (${browser})`,
        user_agent: ua,
        screen_info: `${screen.width}x${screen.height}`,
        language: navigator.language || ''
    };
}

// Exporter pour utilisation globale
window.DeviceFingerprint = {
    generate: generateDeviceFingerprint,
    generateSecure: generateSecureFingerprint,
    getDeviceInfo: getDeviceInfo
};
