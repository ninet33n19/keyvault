use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::rand_core::{OsRng as ArgonRng, RngCore},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json;
use tauri::{AppHandle, Manager};

#[derive(Serialize)]
pub struct Credential {
    id: i64,
    title: String,
    provider_name: String,
    notes: String,
    status: String,
    api_key: String,
    api_secret: String,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedField {
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[tauri::command]
pub async fn add_credential(
    app_handle: AppHandle,
    title: String,
    provider_name: String,
    notes: String,
    status: String,
    api_key: String,
    api_secret: String,
    master_password: String,
) -> Result<(), String> {
    // ---- 1. DERIVE ENCRYPTION KEY from master password using a per-record random salt ----
    let argon2 = Argon2::default();

    let mut salt = [0u8; 16];
    ArgonRng.fill_bytes(&mut salt);

    let mut encryption_key = [0u8; 32];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut encryption_key)
        .map_err(|e| e.to_string())?;

    // ---- 2. ENCRYPT THE SECRETS with distinct nonces ----
    let cipher = Aes256Gcm::new_from_slice(&encryption_key).map_err(|e| e.to_string())?;

    // Encrypt API key
    let mut nonce_key = [0u8; 12];
    ArgonRng.fill_bytes(&mut nonce_key);
    let encrypted_api_key_ct = cipher
        .encrypt(Nonce::from_slice(&nonce_key), api_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let encrypted_api_key = EncryptedField {
        salt_b64: general_purpose::STANDARD.encode(&salt),
        nonce_b64: general_purpose::STANDARD.encode(&nonce_key),
        ciphertext_b64: general_purpose::STANDARD.encode(&encrypted_api_key_ct),
    };
    let encrypted_api_key = serde_json::to_vec(&encrypted_api_key).map_err(|e| e.to_string())?;

    // Encrypt API secret (reuse key, new nonce)
    let mut nonce_secret = [0u8; 12];
    ArgonRng.fill_bytes(&mut nonce_secret);
    let encrypted_api_secret_ct = cipher
        .encrypt(Nonce::from_slice(&nonce_secret), api_secret.as_bytes())
        .map_err(|e| e.to_string())?;
    let encrypted_api_secret = EncryptedField {
        salt_b64: general_purpose::STANDARD.encode(&salt),
        nonce_b64: general_purpose::STANDARD.encode(&nonce_secret),
        ciphertext_b64: general_purpose::STANDARD.encode(&encrypted_api_secret_ct),
    };
    let encrypted_api_secret =
        serde_json::to_vec(&encrypted_api_secret).map_err(|e| e.to_string())?;

    // ---- 3. SAVE TO DATABASE ----
    let db_path = app_handle
        .path()
        .app_data_dir()
        .unwrap()
        .join("keyvault.db");
    let conn = rusqlite::Connection::open(db_path).map_err(|e| e.to_string())?;

    let sql = "
        INSERT INTO credentials (title, provider_name, notes, status, encrypted_key, encrypted_secret)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
    ";

    conn.execute(
        sql,
        params![
            title,
            provider_name,
            notes,
            status,
            encrypted_api_key,
            encrypted_api_secret,
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn search_credentials(
    app_handle: AppHandle,
    master_password: String,
    search_query: Option<String>,
    filter_by_provider: Option<String>,
) -> Result<Vec<Credential>, String> {
    // ---- 1. BUILD DYNAMIC SQL QUERY ----
    let db_path = app_handle
        .path()
        .app_data_dir()
        .unwrap()
        .join("keyvault.db");
    let conn = rusqlite::Connection::open(db_path).map_err(|e| e.to_string())?;

    let mut sql = "SELECT * FROM credentials WHERE 1=1".to_string();
    let mut params_vec: Vec<String> = Vec::new();

    if let Some(query) = search_query {
        sql.push_str(" AND (title LIKE ? OR notes LIKE ?)");
        params_vec.push(format!("%{}%", query));
        params_vec.push(format!("%{}%", query));
    }
    if let Some(provider) = filter_by_provider {
        sql.push_str(" AND provider_name = ?");
        params_vec.push(provider);
    }

    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let mut rows = stmt
        .query(rusqlite::params_from_iter(params_vec.iter()))
        .map_err(|e| e.to_string())?;

    // ---- 2. FETCH AND DECRYPT ----
    let mut credentials = Vec::new();
    let argon2 = Argon2::default();

    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        // Retrieve encrypted blobs
        let encrypted_key_blob: Vec<u8> = row.get("encrypted_key").map_err(|e| e.to_string())?;
        let encrypted_secret_blob: Vec<u8> =
            row.get("encrypted_secret").map_err(|e| e.to_string())?;

        // Parse JSON envelopes
        let enc_key: EncryptedField =
            serde_json::from_slice(&encrypted_key_blob).map_err(|e| e.to_string())?;
        let enc_secret: EncryptedField =
            serde_json::from_slice(&encrypted_secret_blob).map_err(|e| e.to_string())?;

        // Decode components for API key
        let salt_key = general_purpose::STANDARD
            .decode(enc_key.salt_b64.as_bytes())
            .map_err(|e| e.to_string())?;
        let nonce_key = general_purpose::STANDARD
            .decode(enc_key.nonce_b64.as_bytes())
            .map_err(|e| e.to_string())?;
        let ct_key = general_purpose::STANDARD
            .decode(enc_key.ciphertext_b64.as_bytes())
            .map_err(|e| e.to_string())?;

        // Derive key and decrypt API key
        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(master_password.as_bytes(), &salt_key, &mut derived_key)
            .map_err(|e| e.to_string())?;
        let cipher_key = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| e.to_string())?;
        let api_key_bytes = cipher_key
            .decrypt(Nonce::from_slice(&nonce_key), ct_key.as_ref())
            .map_err(|e| e.to_string())?;
        let api_key = String::from_utf8(api_key_bytes).map_err(|e| e.to_string())?;

        // Decode components for API secret
        let salt_secret = general_purpose::STANDARD
            .decode(enc_secret.salt_b64.as_bytes())
            .map_err(|e| e.to_string())?;
        let nonce_secret = general_purpose::STANDARD
            .decode(enc_secret.nonce_b64.as_bytes())
            .map_err(|e| e.to_string())?;
        let ct_secret = general_purpose::STANDARD
            .decode(enc_secret.ciphertext_b64.as_bytes())
            .map_err(|e| e.to_string())?;

        // Derive key and decrypt API secret
        let mut derived_key_secret = [0u8; 32];
        argon2
            .hash_password_into(
                master_password.as_bytes(),
                &salt_secret,
                &mut derived_key_secret,
            )
            .map_err(|e| e.to_string())?;
        let cipher_secret =
            Aes256Gcm::new_from_slice(&derived_key_secret).map_err(|e| e.to_string())?;
        let api_secret_bytes = cipher_secret
            .decrypt(Nonce::from_slice(&nonce_secret), ct_secret.as_ref())
            .map_err(|e| e.to_string())?;
        let api_secret = String::from_utf8(api_secret_bytes).map_err(|e| e.to_string())?;

        let id: i64 = row.get("id").map_err(|e| e.to_string())?;
        let title: String = row.get("title").map_err(|e| e.to_string())?;
        let provider_name: String = row.get("provider_name").map_err(|e| e.to_string())?;
        let notes: String = row.get("notes").map_err(|e| e.to_string())?;
        let status: String = row.get("status").map_err(|e| e.to_string())?;
        let created_at: String = row.get("created_at").map_err(|e| e.to_string())?;

        credentials.push(Credential {
            id,
            title,
            provider_name,
            notes,
            status,
            created_at,
            api_key,
            api_secret,
        });
    }

    Ok(credentials)
}

#[tauri::command]
pub async fn get_single_credential(
    app_handle: AppHandle,
    master_password: String,
    id: i64,
) -> Result<Credential, String> {
    // ---- 1. FETCH THE SINGLE ROW BY ID ----
    let db_path = app_handle
        .path()
        .app_data_dir()
        .unwrap()
        .join("keyvault.db");
    let conn = rusqlite::Connection::open(db_path).map_err(|e| e.to_string())?;

    let sql = "SELECT * FROM credentials WHERE id = ?1";

    // Get all fields including encrypted blobs
    let (
        row_id,
        title,
        provider_name,
        notes,
        status,
        created_at,
        encrypted_key_blob,
        encrypted_secret_blob,
    ): (
        i64,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
    ) = conn
        .query_row(sql, params![id], |row| {
            Ok((
                row.get("id")?,
                row.get("title")?,
                row.get("provider_name")?,
                row.get("notes")?,
                row.get("status")?,
                row.get("created_at")?,
                row.get("encrypted_key")?,
                row.get("encrypted_secret")?,
            ))
        })
        .map_err(|e| e.to_string())?;

    // ---- 2. DECRYPT USING STORED SALT AND NONCE ----
    let argon2 = Argon2::default();

    // API key
    let enc_key: EncryptedField =
        serde_json::from_slice(&encrypted_key_blob).map_err(|e| e.to_string())?;
    let salt_key = general_purpose::STANDARD
        .decode(enc_key.salt_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let nonce_key = general_purpose::STANDARD
        .decode(enc_key.nonce_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let ct_key = general_purpose::STANDARD
        .decode(enc_key.ciphertext_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt_key, &mut derived_key)
        .map_err(|e| e.to_string())?;
    let cipher_key = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| e.to_string())?;
    let api_key_bytes = cipher_key
        .decrypt(Nonce::from_slice(&nonce_key), ct_key.as_ref())
        .map_err(|e| e.to_string())?;
    let api_key = String::from_utf8(api_key_bytes).map_err(|e| e.to_string())?;

    // API secret
    let enc_secret: EncryptedField =
        serde_json::from_slice(&encrypted_secret_blob).map_err(|e| e.to_string())?;
    let salt_secret = general_purpose::STANDARD
        .decode(enc_secret.salt_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let nonce_secret = general_purpose::STANDARD
        .decode(enc_secret.nonce_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let ct_secret = general_purpose::STANDARD
        .decode(enc_secret.ciphertext_b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut derived_key_secret = [0u8; 32];
    argon2
        .hash_password_into(
            master_password.as_bytes(),
            &salt_secret,
            &mut derived_key_secret,
        )
        .map_err(|e| e.to_string())?;
    let cipher_secret =
        Aes256Gcm::new_from_slice(&derived_key_secret).map_err(|e| e.to_string())?;
    let api_secret_bytes = cipher_secret
        .decrypt(Nonce::from_slice(&nonce_secret), ct_secret.as_ref())
        .map_err(|e| e.to_string())?;
    let api_secret = String::from_utf8(api_secret_bytes).map_err(|e| e.to_string())?;

    Ok(Credential {
        id: row_id,
        title,
        provider_name,
        notes,
        status,
        created_at,
        api_key,
        api_secret,
    })
}

#[tauri::command]
pub async fn delete_credential(app_handle: AppHandle, id: i64) -> Result<(), String> {
    let db_path = app_handle
        .path()
        .app_data_dir()
        .unwrap()
        .join("keyvault.db");
    let conn = rusqlite::Connection::open(db_path).map_err(|e| e.to_string())?;

    let sql = "DELETE FROM credentials WHERE id = ?1";

    conn.execute(sql, params![id]).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn update_credential(
    app_handle: AppHandle,
    id: i64,
    title: String,
    provider_name: String,
    notes: String,
    status: String,
    api_key: String,
    api_secret: String,
    master_password: String,
) -> Result<(), String> {
    // ---- 1. DERIVE ENCRYPTION KEY from master password using a new random salt ----
    let argon2 = Argon2::default();

    let mut salt = [0u8; 16];
    ArgonRng.fill_bytes(&mut salt);

    let mut encryption_key = [0u8; 32];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut encryption_key)
        .map_err(|e| e.to_string())?;

    // ---- 2. ENCRYPT THE NEW SECRETS with distinct nonces ----
    let cipher = Aes256Gcm::new_from_slice(&encryption_key).map_err(|e| e.to_string())?;

    // Encrypt API key
    let mut nonce_key = [0u8; 12];
    ArgonRng.fill_bytes(&mut nonce_key);
    let encrypted_api_key_ct = cipher
        .encrypt(Nonce::from_slice(&nonce_key), api_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let encrypted_api_key = EncryptedField {
        salt_b64: general_purpose::STANDARD.encode(&salt),
        nonce_b64: general_purpose::STANDARD.encode(&nonce_key),
        ciphertext_b64: general_purpose::STANDARD.encode(&encrypted_api_key_ct),
    };
    let encrypted_api_key = serde_json::to_vec(&encrypted_api_key).map_err(|e| e.to_string())?;

    // Encrypt API secret
    let mut nonce_secret = [0u8; 12];
    ArgonRng.fill_bytes(&mut nonce_secret);
    let encrypted_api_secret_ct = cipher
        .encrypt(Nonce::from_slice(&nonce_secret), api_secret.as_bytes())
        .map_err(|e| e.to_string())?;
    let encrypted_api_secret = EncryptedField {
        salt_b64: general_purpose::STANDARD.encode(&salt),
        nonce_b64: general_purpose::STANDARD.encode(&nonce_secret),
        ciphertext_b64: general_purpose::STANDARD.encode(&encrypted_api_secret_ct),
    };
    let encrypted_api_secret =
        serde_json::to_vec(&encrypted_api_secret).map_err(|e| e.to_string())?;

    // ---- 3. UPDATE THE DATABASE ----
    let db_path = app_handle
        .path()
        .app_data_dir()
        .unwrap()
        .join("keyvault.db");
    let conn = rusqlite::Connection::open(db_path).map_err(|e| e.to_string())?;

    let sql = "
        UPDATE credentials
        SET title = ?1, provider_name = ?2, notes = ?3, status = ?4, encrypted_key = ?5, encrypted_secret = ?6
        WHERE id = ?7
    ";

    conn.execute(
        sql,
        params![
            title,
            provider_name,
            notes,
            status,
            encrypted_api_key,
            encrypted_api_secret,
            id,
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}
