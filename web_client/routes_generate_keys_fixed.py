@app.route('/generate-keys', methods=['GET', 'POST'])
@login_required  
def generate_keys():
    """
    GET: Détecte si premier setup ou nouvel appareil nécessitant QR
    POST: Enregistre les clés du premier appareil
    """
    username = session.get('username')
    
    if request.method == 'GET':
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))
        from lib.auth.device_manager import has_registered_key, is_device_authorized
        
        # Vérifier si l'user a déjà des clés
        has_keys = has_registered_key(username)
        
        if has_keys:
            # User a déjà des clés → Vérifier si CET appareil est autorisé
            # On utilise un fingerprint temporaire côté client
            # Pour l'instant on redirige vers QR
            print(f"[QR WORKFLOW] {username} has keys, redirecting to QR authorization")
            return redirect(url_for('qr_request_authorization'))
        else:
            # Pas de clés → Setup initial (premier appareil)
            print(f"[SETUP] {username} first device, showing setup page")
            return render_template('setup_keys.html')
    
    # POST : Enregistrement des clés (premier appareil)
    data = request.get_json()
    
    encrypted_private_key = data.get('encrypted_private_key')
    salt = data.get('salt')
    iv = data.get('iv')
    public_key = data.get('public_key')
    device_info = data.get('device_info', {})
    device_fingerprint = data.get('device_fingerprint')
    device_public_key_ed25519 = data.get('device_public_key_ed25519')
    
    if not all([encrypted_private_key, salt, iv, public_key, device_fingerprint, device_public_key_ed25519]):
        return jsonify({'success': False, 'error': 'Données manquantes'}), 400
    
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.device_manager import register_device, has_registered_key
    
    # Vérifier qu'il n'y a pas déjà de clés
    if has_registered_key(username):
        return jsonify({'success': False, 'error': 'Clés déjà enregistrées'}), 400
    
    # Enregistrer le premier appareil (authorized_by = None car c'est le maître)
    result = register_device(
        username=username,
        device_fingerprint=device_fingerprint,
        device_info=device_info,
        encrypted_private_key=encrypted_private_key,
        salt=salt,
        iv=iv,
        device_public_key_ed25519=device_public_key_ed25519,
        authorized_by_device_id=None  # Premier appareil = maître
    )
    
    if not result['success']:
        return jsonify(result), 400
    
    # Sauvegarder la clé publique au format PEM pour compatibilité serveur
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    
    try:
        # Décoder la clé publique raw
        public_key_bytes = base64.b64decode(public_key)
        
        # Importer la clé publique (P-256, 65 bytes)
        public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            public_key_bytes
        )
        
        # Exporter en format PEM
        public_key_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Sauvegarder localement
        user_keys_dir = os.path.join(USER_KEYS_DIR, username)
        os.makedirs(user_keys_dir, exist_ok=True)
        pubkey_path = os.path.join(user_keys_dir, 'public_key.pem')
        
        with open(pubkey_path, 'wb') as f:
            f.write(public_key_pem)
        
        # Copier vers storage
        storage_user_dir = os.path.join(STORAGE_DIR, username)
        os.makedirs(storage_user_dir, exist_ok=True)
        import shutil
        shutil.copy(pubkey_path, os.path.join(storage_user_dir, 'public_key.pem'))
        
        print(f"[KEYS ZK] ✅ Clé publique sauvegardée pour {username}")
        
    except Exception as e:
        print(f"[KEYS ZK] ❌ Erreur traitement clé publique: {e}")
        return jsonify({'success': False, 'error': f'Erreur clé publique: {str(e)}'}), 500
    
    # Logger l'action
    logger = get_activity_logger()
    logger.log_activity(
        username, 'KEY_GENERATION', request.remote_addr,
        'SUCCESS', f'Premier appareil configuré: {device_info.get("device_name", "Unknown")}',
        user_agent=request.headers.get('User-Agent', '')
    )
    
    print(f"[KEYS ZK] ✅ Configuration Zero-Knowledge réussie pour {username}")
    return jsonify({
        'success': True,
        'device_id': result['device_id'],
        'message': 'Clés configurées en mode Zero-Knowledge'
    })
