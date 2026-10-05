#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use arboard::Clipboard;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    Key, XChaCha20Poly1305, XNonce,
};
use chrono::{SecondsFormat, Utc};
use rand::{rngs::OsRng, seq::SliceRandom, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};
use tauri::{Manager, RunEvent, State};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const VAULT_FORMAT: &str = "pmvault";
const VAULT_VERSION: u32 = 1;
const PAYLOAD_ALGORITHM: &str = "xchacha20-poly1305-payload-v1";
const KEY_WRAP_ALGORITHM: &str = "xchacha20-poly1305-key-wrap-v1";
const KEY_WRAP_AAD: &[u8] = b"pmvault/key-wrap/v1";
const PAYLOAD_AAD: &[u8] = b"pmvault/payload/v1";
const DEFAULT_VAULT_FILE: &str = "vault.pmvault";
const DEFAULT_AUTO_LOCK_SECONDS: u64 = 15 * 60;
const DEFAULT_CLIPBOARD_CLEAR_SECONDS: u64 = 30;
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Error)]
enum CoreError {
    #[error("storage")]
    Storage(#[source] io::Error),
    #[error("format")]
    Format,
    #[error("authentication")]
    Authentication,
    #[error("crypto")]
    Crypto,
    #[error("serialization")]
    Serialization(#[source] serde_json::Error),
    #[error("clipboard")]
    Clipboard,
    #[error("invalid input")]
    InvalidInput,
}

type CoreResult<T> = Result<T, CoreError>;
type CommandResult<T> = Result<T, CommandError>;

#[derive(Debug, Clone, Serialize)]
struct CommandError {
    code: String,
    message: String,
}

impl CommandError {
    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    fn user_input(message: &str) -> Self {
        Self::new("UserInputError", message)
    }

    fn locked() -> Self {
        Self::new("AuthenticationError", "请先解锁密码库。")
    }
}

fn map_core_error(error: CoreError) -> CommandError {
    eprintln!("[vaultroom] core operation failed: {error}");
    match error {
        CoreError::Authentication => CommandError::new(
            "AuthenticationError",
            "无法解锁密码库，请检查主密码或密码库文件。",
        ),
        CoreError::Format => {
            CommandError::new("VaultFormatError", "密码库文件格式无效、不受支持或已损坏。")
        }
        CoreError::Storage(_) => CommandError::new(
            "StorageError",
            "无法读写密码库文件，请检查文件权限和磁盘空间。",
        ),
        CoreError::Clipboard => {
            CommandError::new("ClipboardError", "无法访问系统剪贴板，请稍后重试。")
        }
        CoreError::Crypto => CommandError::new(
            "CryptoError",
            "加密操作失败，当前操作已中止，原有数据未被清除。",
        ),
        CoreError::Serialization(_) => {
            CommandError::new("InternalError", "无法保存当前数据，请重试。")
        }
        CoreError::InvalidInput => CommandError::user_input("输入内容无效，请检查后重试。"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    salt: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyWrap {
    algorithm: String,
    nonce: String,
    wrapped_dek: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Payload {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    kdf: KdfParams,
    key_wrap: KeyWrap,
    payload: Payload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultData {
    version: u32,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    entries: Vec<PasswordEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordEntry {
    id: String,
    title: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: bool,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    custom_fields: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryInput {
    title: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    custom_fields: Option<HashMap<String, String>>,
}

impl Drop for EntryInput {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        for tag in &mut self.tags {
            tag.zeroize();
        }
        if let Some(fields) = &mut self.custom_fields {
            for value in fields.values_mut() {
                value.zeroize();
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntrySummary {
    id: String,
    title: String,
    username: String,
    url: String,
    tags: Vec<String>,
    favorite: bool,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryFilter {
    #[serde(default = "default_scope")]
    scope: String,
    #[serde(default)]
    tag: Option<String>,
}

fn default_scope() -> String {
    "all".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppSettings {
    auto_lock_seconds: u64,
    clipboard_clear_seconds: u64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_lock_seconds: DEFAULT_AUTO_LOCK_SECONDS,
            clipboard_clear_seconds: DEFAULT_CLIPBOARD_CLEAR_SECONDS,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStateDto {
    vault_exists: bool,
    locked: bool,
    vault_path_display_name: Option<String>,
    auto_lock_seconds_remaining: Option<u64>,
    app_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClipboardStatus {
    clear_after_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordGeneratorOptions {
    #[serde(default = "default_password_length")]
    length: usize,
    #[serde(default = "default_true")]
    include_uppercase: bool,
    #[serde(default = "default_true")]
    include_lowercase: bool,
    #[serde(default = "default_true")]
    include_numbers: bool,
    #[serde(default = "default_true")]
    include_symbols: bool,
    #[serde(default)]
    exclude_ambiguous: bool,
}

fn default_password_length() -> usize {
    20
}

fn default_true() -> bool {
    true
}

#[derive(Clone)]
struct UnlockedVault {
    dek: [u8; 32],
    data: VaultData,
    kdf: KdfParams,
    key_wrap: KeyWrap,
}

struct ManagedClipboard {
    digest: Option<[u8; 32]>,
    generation: u64,
}

struct CoreState {
    app_data_dir: PathBuf,
    vault_path: PathBuf,
    settings: AppSettings,
    unlocked: Option<UnlockedVault>,
    last_activity: Instant,
    managed_clipboard: ManagedClipboard,
}

#[derive(Clone)]
struct AppState(Arc<Mutex<CoreState>>);

fn lock_state(state: &AppState) -> CommandResult<MutexGuard<'_, CoreState>> {
    state
        .0
        .lock()
        .map_err(|_| CommandError::new("InternalError", "应用状态不可用，请重启应用。"))
}

fn now_string() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    bytes
}

fn encode_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_bytes(value: &str) -> CoreResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| CoreError::Format)
}

fn derive_kek(password: &str, params: &KdfParams) -> CoreResult<[u8; 32]> {
    let salt = decode_bytes(&params.salt)?;
    if salt.len() < 16 || params.memory_kib < 8 * 1024 || params.memory_kib > 1024 * 1024 {
        return Err(CoreError::Format);
    }
    if params.iterations == 0 || params.parallelism == 0 || params.parallelism > 32 {
        return Err(CoreError::Format);
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| CoreError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0_u8; 32];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|_| CoreError::Crypto)?;
    Ok(key)
}

fn new_kdf_params() -> KdfParams {
    KdfParams {
        algorithm: "argon2id".to_string(),
        salt: encode_bytes(&random_array::<16>()),
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    }
}

fn encrypt_aead(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> CoreResult<(Vec<u8>, [u8; 24])> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = random_array::<24>();
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            AeadPayload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::Crypto)?;
    Ok((encrypted, nonce))
}

fn decrypt_aead(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> CoreResult<Vec<u8>> {
    if nonce.len() != 24 {
        return Err(CoreError::Format);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            AeadPayload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::Authentication)
}

fn validate_vault_file(file: &VaultFile) -> CoreResult<()> {
    if file.format != VAULT_FORMAT || file.version != VAULT_VERSION {
        return Err(CoreError::Format);
    }
    if file.kdf.algorithm != "argon2id"
        || file.key_wrap.algorithm != KEY_WRAP_ALGORITHM
        || file.payload.algorithm != PAYLOAD_ALGORITHM
    {
        return Err(CoreError::Format);
    }
    let salt = decode_bytes(&file.kdf.salt)?;
    let wrap_nonce = decode_bytes(&file.key_wrap.nonce)?;
    let payload_nonce = decode_bytes(&file.payload.nonce)?;
    let wrapped_dek = decode_bytes(&file.key_wrap.wrapped_dek)?;
    let ciphertext = decode_bytes(&file.payload.ciphertext)?;
    if salt.len() < 16
        || wrap_nonce.len() != 24
        || payload_nonce.len() != 24
        || wrapped_dek.len() < 32
        || ciphertext.len() < 16
    {
        return Err(CoreError::Format);
    }
    if file.kdf.memory_kib < 8 * 1024
        || file.kdf.memory_kib > 1024 * 1024
        || file.kdf.iterations == 0
        || file.kdf.parallelism == 0
        || file.kdf.parallelism > 32
    {
        return Err(CoreError::Format);
    }
    Ok(())
}

fn validate_entry(entry: &PasswordEntry) -> CoreResult<()> {
    if Uuid::parse_str(&entry.id).is_err() || entry.title.trim().is_empty() {
        return Err(CoreError::Format);
    }
    if entry.title.chars().count() > 512
        || entry.username.chars().count() > 4096
        || entry.password.chars().count() > 4096
        || entry.url.chars().count() > 4096
        || entry.notes.chars().count() > 50_000
        || entry.tags.len() > 128
        || entry.custom_fields.len() > 128
    {
        return Err(CoreError::Format);
    }
    Ok(())
}

fn validate_vault_data(data: &VaultData) -> CoreResult<()> {
    if data.version != VAULT_VERSION || data.entries.len() > MAX_ENTRIES {
        return Err(CoreError::Format);
    }
    for entry in &data.entries {
        validate_entry(entry)?;
    }
    Ok(())
}

fn read_vault_container(path: &Path) -> CoreResult<VaultFile> {
    let metadata = fs::metadata(path).map_err(CoreError::Storage)?;
    if !metadata.is_file() || metadata.len() > MAX_VAULT_BYTES {
        return Err(CoreError::Format);
    }
    let bytes = fs::read(path).map_err(CoreError::Storage)?;
    let file = serde_json::from_slice::<VaultFile>(&bytes).map_err(|_| CoreError::Format)?;
    validate_vault_file(&file)?;
    Ok(file)
}

fn open_vault_file(path: &Path, password: &str) -> CoreResult<UnlockedVault> {
    let file = read_vault_container(path)?;
    let mut kek = derive_kek(password, &file.kdf)?;
    let nonce = decode_bytes(&file.key_wrap.nonce)?;
    let wrapped_dek = decode_bytes(&file.key_wrap.wrapped_dek)?;
    let mut dek_bytes = decrypt_aead(&kek, &wrapped_dek, &nonce, KEY_WRAP_AAD)?;
    if dek_bytes.len() != 32 {
        dek_bytes.zeroize();
        kek.zeroize();
        return Err(CoreError::Authentication);
    }
    let mut dek = [0_u8; 32];
    dek.copy_from_slice(&dek_bytes);
    dek_bytes.zeroize();

    let payload_nonce = decode_bytes(&file.payload.nonce)?;
    let ciphertext = decode_bytes(&file.payload.ciphertext)?;
    let mut plaintext = decrypt_aead(&dek, &ciphertext, &payload_nonce, PAYLOAD_AAD)?;
    let data = serde_json::from_slice::<VaultData>(&plaintext).map_err(|_| CoreError::Format)?;
    plaintext.zeroize();
    validate_vault_data(&data)?;
    kek.zeroize();

    Ok(UnlockedVault {
        dek,
        data,
        kdf: file.kdf,
        key_wrap: file.key_wrap,
    })
}

fn build_vault_file(
    kdf: KdfParams,
    key_wrap: KeyWrap,
    dek: &[u8; 32],
    data: &VaultData,
) -> CoreResult<VaultFile> {
    validate_vault_data(data)?;
    let plaintext = serde_json::to_vec(data).map_err(CoreError::Serialization)?;
    let (ciphertext, nonce) = encrypt_aead(dek, &plaintext, PAYLOAD_AAD)?;
    Ok(VaultFile {
        format: VAULT_FORMAT.to_string(),
        version: VAULT_VERSION,
        kdf,
        key_wrap,
        payload: Payload {
            algorithm: PAYLOAD_ALGORITHM.to_string(),
            nonce: encode_bytes(&nonce),
            ciphertext: encode_bytes(&ciphertext),
        },
    })
}

fn create_unlocked_vault(path: &Path, password: &str) -> CoreResult<UnlockedVault> {
    let kdf = new_kdf_params();
    let mut kek = derive_kek(password, &kdf)?;
    let mut dek = random_array::<32>();
    let (wrapped_dek, wrap_nonce) = encrypt_aead(&kek, &dek, KEY_WRAP_AAD)?;
    let key_wrap = KeyWrap {
        algorithm: KEY_WRAP_ALGORITHM.to_string(),
        nonce: encode_bytes(&wrap_nonce),
        wrapped_dek: encode_bytes(&wrapped_dek),
    };
    let timestamp = now_string();
    let data = VaultData {
        version: VAULT_VERSION,
        created_at: timestamp.clone(),
        updated_at: timestamp,
        entries: Vec::new(),
    };
    let file = build_vault_file(kdf.clone(), key_wrap.clone(), &dek, &data)?;
    write_vault_file_atomically(path, &file)?;
    kek.zeroize();
    let session = UnlockedVault {
        dek,
        data,
        kdf,
        key_wrap,
    };
    dek.zeroize();
    Ok(session)
}

fn backup_path(path: &Path, index: u8) -> PathBuf {
    path.with_extension(format!("pmbackup.{index}"))
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vault");
    path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()))
}

fn write_temporary_file(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(CoreError::Storage)?;
    file.write_all(bytes).map_err(CoreError::Storage)?;
    file.sync_all().map_err(CoreError::Storage)?;
    Ok(())
}

fn sync_file(path: &Path) -> CoreResult<()> {
    let file = File::open(path).map_err(CoreError::Storage)?;
    file.sync_all().map_err(CoreError::Storage)
}

fn rotate_backup_slots(path: &Path) -> CoreResult<()> {
    let third = backup_path(path, 3);
    let second = backup_path(path, 2);
    let first = backup_path(path, 1);
    if third.exists() {
        fs::remove_file(&third).map_err(CoreError::Storage)?;
    }
    if second.exists() {
        fs::rename(&second, &third).map_err(CoreError::Storage)?;
    }
    if first.exists() {
        fs::rename(&first, &second).map_err(CoreError::Storage)?;
    }
    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
fn atomic_replace(temp: &Path, destination: &Path, backup: Option<&Path>) -> CoreResult<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    if !destination.exists() {
        fs::rename(temp, destination).map_err(CoreError::Storage)?;
        return Ok(());
    }
    let destination_w = wide_path(destination);
    let temp_w = wide_path(temp);
    let backup_w = backup.map(wide_path);
    let backup_ptr = backup_w
        .as_ref()
        .map(|value| value.as_ptr())
        .unwrap_or(std::ptr::null());
    let result = unsafe {
        ReplaceFileW(
            destination_w.as_ptr(),
            temp_w.as_ptr(),
            backup_ptr,
            0,
            null_mut(),
            null_mut(),
        )
    };
    if result == 0 {
        return Err(CoreError::Storage(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(temp: &Path, destination: &Path, backup: Option<&Path>) -> CoreResult<()> {
    if destination.exists() {
        if let Some(backup_path) = backup {
            fs::copy(destination, backup_path).map_err(CoreError::Storage)?;
            sync_file(backup_path)?;
        }
    }
    fs::rename(temp, destination).map_err(CoreError::Storage)
}

fn write_bytes_atomically(path: &Path, bytes: &[u8], keep_backup: bool) -> CoreResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(CoreError::Storage)?;
    }
    let temp = temporary_path(path);
    write_temporary_file(&temp, bytes)?;

    let backup = if keep_backup && path.exists() {
        rotate_backup_slots(path)?;
        Some(backup_path(path, 1))
    } else {
        None
    };

    let result = atomic_replace(&temp, path, backup.as_deref());
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_vault_file_atomically(path: &Path, file: &VaultFile) -> CoreResult<()> {
    let bytes = serde_json::to_vec_pretty(file).map_err(CoreError::Serialization)?;
    write_bytes_atomically(path, &bytes, true)
}

fn write_settings(path: &Path, settings: &AppSettings) -> CoreResult<()> {
    let bytes = serde_json::to_vec_pretty(settings).map_err(CoreError::Serialization)?;
    write_bytes_atomically(path, &bytes, false)
}

fn settings_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("settings.json")
}

fn load_settings(app_data_dir: &Path) -> AppSettings {
    let path = settings_path(app_data_dir);
    let Ok(bytes) = fs::read(path) else {
        return AppSettings::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn validate_vault_selection(path: &Path, must_exist: bool) -> CoreResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(CoreError::InvalidInput);
    }
    if must_exist {
        let metadata = fs::metadata(path).map_err(CoreError::Storage)?;
        if !metadata.is_file() || metadata.len() > MAX_VAULT_BYTES {
            return Err(CoreError::Format);
        }
        return path.canonicalize().map_err(CoreError::Storage);
    }
    let parent = path.parent().ok_or(CoreError::InvalidInput)?;
    if !parent.exists() || !parent.is_dir() {
        return Err(CoreError::Storage(io::Error::new(
            io::ErrorKind::NotFound,
            "destination directory does not exist",
        )));
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if extension != "pmvault" {
        return Err(CoreError::InvalidInput);
    }
    Ok(path.to_path_buf())
}

fn normalized_tags(tags: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for tag in tags {
        let value = tag.trim();
        if value.is_empty() {
            continue;
        }
        if !result
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(value))
        {
            result.push(value.to_string());
        }
    }
    result.truncate(32);
    result
}

fn make_entry(input: &EntryInput, existing: Option<&PasswordEntry>) -> PasswordEntry {
    let timestamp = now_string();
    PasswordEntry {
        id: existing
            .map(|entry| entry.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        title: input.title.trim().to_string(),
        username: input.username.trim().to_string(),
        password: input.password.clone(),
        url: input.url.trim().to_string(),
        notes: input.notes.clone(),
        tags: normalized_tags(&input.tags),
        favorite: input.favorite,
        created_at: existing
            .map(|entry| entry.created_at.clone())
            .unwrap_or_else(|| timestamp.clone()),
        updated_at: timestamp,
        custom_fields: input.custom_fields.clone().unwrap_or_default(),
    }
}

fn to_summary(entry: &PasswordEntry) -> EntrySummary {
    EntrySummary {
        id: entry.id.clone(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        url: entry.url.clone(),
        tags: entry.tags.clone(),
        favorite: entry.favorite,
        updated_at: entry.updated_at.clone(),
    }
}

fn persist_session(core: &mut CoreState) -> CoreResult<()> {
    let session = core.unlocked.as_ref().ok_or(CoreError::Authentication)?;
    let file = build_vault_file(
        session.kdf.clone(),
        session.key_wrap.clone(),
        &session.dek,
        &session.data,
    )?;
    write_vault_file_atomically(&core.vault_path, &file)
}

fn clear_managed_clipboard_internal(core: &mut CoreState) -> CoreResult<()> {
    let expected = core.managed_clipboard.digest.take();
    core.managed_clipboard.generation = core.managed_clipboard.generation.wrapping_add(1);
    let Some(expected) = expected else {
        return Ok(());
    };
    let mut clipboard = Clipboard::new().map_err(|_| CoreError::Clipboard)?;
    let current = clipboard.get_text().map_err(|_| CoreError::Clipboard)?;
    let current_digest = Sha256::digest(current.as_bytes());
    if current_digest.as_slice() == expected {
        clipboard
            .set_text(String::new())
            .map_err(|_| CoreError::Clipboard)?;
    }
    Ok(())
}

fn lock_vault_internal(core: &mut CoreState) {
    if let Some(mut session) = core.unlocked.take() {
        session.dek.zeroize();
        for entry in &mut session.data.entries {
            entry.id.zeroize();
            entry.title.zeroize();
            entry.username.zeroize();
            entry.password.zeroize();
            entry.url.zeroize();
            entry.notes.zeroize();
            for tag in &mut entry.tags {
                tag.zeroize();
            }
            for value in entry.custom_fields.values_mut() {
                value.zeroize();
            }
        }
        session.data.entries.clear();
        session.data.created_at.zeroize();
        session.data.updated_at.zeroize();
    }
    if let Err(error) = clear_managed_clipboard_internal(core) {
        eprintln!("[vaultroom] clipboard cleanup failed while locking: {error}");
    }
    core.last_activity = Instant::now();
}

fn start_auto_lock_worker(state: AppState) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let Ok(mut core) = state.0.lock() else {
            continue;
        };
        if core.unlocked.is_some()
            && core.settings.auto_lock_seconds > 0
            && core.last_activity.elapsed() >= Duration::from_secs(core.settings.auto_lock_seconds)
        {
            lock_vault_internal(&mut core);
        }
    });
}

fn mark_activity(core: &mut CoreState) {
    if core.unlocked.is_some() {
        core.last_activity = Instant::now();
    }
}

#[tauri::command]
fn get_app_state(state: State<AppState>) -> CommandResult<AppStateDto> {
    let core = lock_state(state.inner())?;
    let vault_exists = core.vault_path.exists();
    let locked = core.unlocked.is_none();
    let remaining = if !locked && core.settings.auto_lock_seconds > 0 {
        Some(
            core.settings
                .auto_lock_seconds
                .saturating_sub(core.last_activity.elapsed().as_secs()),
        )
    } else {
        None
    };
    let display_name = if vault_exists {
        core.vault_path
            .file_name()
            .and_then(|value| value.to_str())
            .map(ToString::to_string)
    } else {
        None
    };
    Ok(AppStateDto {
        vault_exists,
        locked,
        vault_path_display_name: display_name,
        auto_lock_seconds_remaining: remaining,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> CommandResult<AppSettings> {
    let core = lock_state(state.inner())?;
    Ok(core.settings.clone())
}

#[tauri::command]
fn set_settings(
    auto_lock_seconds: u64,
    clipboard_clear_seconds: u64,
    state: State<AppState>,
) -> CommandResult<AppSettings> {
    if !matches!(auto_lock_seconds, 0 | 300 | 900 | 1800)
        || !(5..=300).contains(&clipboard_clear_seconds)
    {
        return Err(CommandError::user_input("设置值不在支持范围内。"));
    }
    let mut core = lock_state(state.inner())?;
    let previous = core.settings.clone();
    let next = AppSettings {
        auto_lock_seconds,
        clipboard_clear_seconds,
    };
    write_settings(&settings_path(&core.app_data_dir), &next).map_err(map_core_error)?;
    core.settings = next.clone();
    mark_activity(&mut core);
    if next.auto_lock_seconds > 0 {
        core.last_activity = Instant::now();
    }
    if core.settings.auto_lock_seconds == 0 && previous.auto_lock_seconds != 0 {
        core.last_activity = Instant::now();
    }
    Ok(next)
}

#[tauri::command]
fn create_vault(master_password: String, state: State<AppState>) -> CommandResult<()> {
    let master_password = Zeroizing::new(master_password);
    if master_password.trim().is_empty() {
        return Err(CommandError::user_input("主密码不能为空。"));
    }
    let mut core = lock_state(state.inner())?;
    if core.vault_path.exists() {
        return Err(CommandError::user_input(
            "本机已经存在密码库，请直接解锁或打开其他密码库。",
        ));
    }
    let path = core.vault_path.clone();
    let session = create_unlocked_vault(&path, &master_password).map_err(map_core_error)?;
    core.unlocked = Some(session);
    core.last_activity = Instant::now();
    Ok(())
}

#[tauri::command]
fn open_vault(
    master_password: String,
    selected_path: Option<String>,
    state: State<AppState>,
) -> CommandResult<()> {
    let master_password = Zeroizing::new(master_password);
    if master_password.trim().is_empty() {
        return Err(CommandError::user_input("请输入主密码。"));
    }
    let mut core = lock_state(state.inner())?;
    let candidate = selected_path
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| core.vault_path.clone());
    let candidate = validate_vault_selection(&candidate, true).map_err(map_core_error)?;
    let session = open_vault_file(&candidate, &master_password).map_err(map_core_error)?;
    core.vault_path = candidate;
    core.unlocked = Some(session);
    core.last_activity = Instant::now();
    Ok(())
}

#[tauri::command]
fn lock_vault(state: State<AppState>) -> CommandResult<()> {
    let mut core = lock_state(state.inner())?;
    lock_vault_internal(&mut core);
    Ok(())
}

#[tauri::command]
fn close_vault(state: State<AppState>) -> CommandResult<()> {
    let mut core = lock_state(state.inner())?;
    lock_vault_internal(&mut core);
    core.vault_path = core.app_data_dir.join(DEFAULT_VAULT_FILE);
    Ok(())
}

#[tauri::command]
fn record_activity(state: State<AppState>) -> CommandResult<()> {
    let mut core = lock_state(state.inner())?;
    mark_activity(&mut core);
    Ok(())
}

#[tauri::command]
fn change_master_password(
    old_password: String,
    new_password: String,
    state: State<AppState>,
) -> CommandResult<()> {
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);
    if old_password.trim().is_empty() || new_password.trim().is_empty() {
        return Err(CommandError::user_input("主密码不能为空。"));
    }
    let mut core = lock_state(state.inner())?;
    let (old_kdf, old_key_wrap, dek) = {
        let session = core.unlocked.as_ref().ok_or_else(CommandError::locked)?;
        (session.kdf.clone(), session.key_wrap.clone(), session.dek)
    };
    let mut old_kek = derive_kek(&old_password, &old_kdf).map_err(map_core_error)?;
    let old_nonce = decode_bytes(&old_key_wrap.nonce).map_err(map_core_error)?;
    let old_wrapped = decode_bytes(&old_key_wrap.wrapped_dek).map_err(map_core_error)?;
    let mut old_dek = decrypt_aead(&old_kek, &old_wrapped, &old_nonce, KEY_WRAP_AAD)
        .map_err(|_| CommandError::new("AuthenticationError", "旧主密码不正确。"))?;
    old_kek.zeroize();
    if old_dek.len() != 32 || old_dek.as_slice() != dek {
        old_dek.zeroize();
        return Err(CommandError::new("AuthenticationError", "旧主密码不正确。"));
    }
    old_dek.zeroize();

    let new_kdf = new_kdf_params();
    let mut new_kek = derive_kek(&new_password, &new_kdf).map_err(map_core_error)?;
    let (wrapped_dek, nonce) =
        encrypt_aead(&new_kek, &dek, KEY_WRAP_AAD).map_err(map_core_error)?;
    new_kek.zeroize();
    let new_key_wrap = KeyWrap {
        algorithm: KEY_WRAP_ALGORITHM.to_string(),
        nonce: encode_bytes(&nonce),
        wrapped_dek: encode_bytes(&wrapped_dek),
    };

    // Re-wrap the DEK while preserving the already-authenticated payload.
    let path = core.vault_path.clone();
    let mut file = read_vault_container(&path).map_err(map_core_error)?;
    file.kdf = new_kdf.clone();
    file.key_wrap = new_key_wrap.clone();
    write_vault_file_atomically(&path, &file).map_err(map_core_error)?;
    if let Some(session) = core.unlocked.as_mut() {
        session.kdf = new_kdf;
        session.key_wrap = new_key_wrap;
    }
    mark_activity(&mut core);
    Ok(())
}

#[tauri::command]
fn create_backup(state: State<AppState>) -> CommandResult<String> {
    let core = lock_state(state.inner())?;
    if !core.vault_path.exists() {
        return Err(CommandError::new(
            "StorageError",
            "当前还没有可备份的密码库。",
        ));
    }
    let source = core.vault_path.clone();
    drop(core);
    rotate_backup_slots(&source).map_err(map_core_error)?;
    let destination = backup_path(&source, 1);
    fs::copy(&source, &destination)
        .map_err(CoreError::Storage)
        .map_err(map_core_error)?;
    sync_file(&destination).map_err(map_core_error)?;
    Ok(destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("backup")
        .to_string())
}

#[tauri::command]
fn export_vault(destination_path: String, state: State<AppState>) -> CommandResult<()> {
    let destination =
        validate_vault_selection(Path::new(&destination_path), false).map_err(map_core_error)?;
    let core = lock_state(state.inner())?;
    if !core.vault_path.exists() {
        return Err(CommandError::new(
            "StorageError",
            "当前还没有可导出的密码库。",
        ));
    }
    if destination == core.vault_path {
        return Err(CommandError::user_input("导出位置不能与当前密码库相同。"));
    }
    let bytes = fs::read(&core.vault_path)
        .map_err(CoreError::Storage)
        .map_err(map_core_error)?;
    drop(core);
    write_bytes_atomically(&destination, &bytes, false).map_err(map_core_error)
}

#[tauri::command]
fn list_entries(
    query: Option<String>,
    filter: Option<EntryFilter>,
    sort: Option<String>,
    state: State<AppState>,
) -> CommandResult<Vec<EntrySummary>> {
    let mut core = lock_state(state.inner())?;
    let session = core.unlocked.as_ref().ok_or_else(CommandError::locked)?;
    let needle = query.unwrap_or_default().trim().to_lowercase();
    let filter = filter.unwrap_or(EntryFilter {
        scope: default_scope(),
        tag: None,
    });
    let mut entries: Vec<EntrySummary> = session
        .data
        .entries
        .iter()
        .filter(|entry| match filter.scope.as_str() {
            "favorites" => entry.favorite,
            _ => true,
        })
        .filter(|entry| {
            filter.tag.as_ref().map_or(true, |tag| {
                entry
                    .tags
                    .iter()
                    .any(|entry_tag| entry_tag.eq_ignore_ascii_case(tag))
            })
        })
        .filter(|entry| {
            needle.is_empty()
                || entry.title.to_lowercase().contains(&needle)
                || entry.username.to_lowercase().contains(&needle)
                || entry.url.to_lowercase().contains(&needle)
                || entry
                    .tags
                    .iter()
                    .any(|tag| tag.to_lowercase().contains(&needle))
        })
        .map(to_summary)
        .collect();

    entries.sort_by(|left, right| {
        let favorite_order = right.favorite.cmp(&left.favorite);
        if favorite_order != std::cmp::Ordering::Equal {
            return favorite_order;
        }
        match sort.as_deref().unwrap_or("updated_desc") {
            "title_asc" => left.title.to_lowercase().cmp(&right.title.to_lowercase()),
            "title_desc" => right.title.to_lowercase().cmp(&left.title.to_lowercase()),
            _ => right.updated_at.cmp(&left.updated_at),
        }
    });
    mark_activity(&mut core);
    Ok(entries)
}

#[tauri::command]
fn get_entry(id: String, state: State<AppState>) -> CommandResult<PasswordEntry> {
    let mut core = lock_state(state.inner())?;
    let session = core.unlocked.as_ref().ok_or_else(CommandError::locked)?;
    let entry = session
        .data
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .cloned()
        .ok_or_else(|| CommandError::user_input("找不到这条密码记录。"))?;
    mark_activity(&mut core);
    Ok(entry)
}

#[tauri::command]
fn create_entry(input: EntryInput, state: State<AppState>) -> CommandResult<EntrySummary> {
    if input.title.trim().is_empty() {
        return Err(CommandError::user_input("标题不能为空。"));
    }
    let mut core = lock_state(state.inner())?;
    let session = core.unlocked.as_mut().ok_or_else(CommandError::locked)?;
    let previous = session.data.clone();
    let entry = make_entry(&input, None);
    session.data.entries.push(entry.clone());
    session.data.updated_at = now_string();
    if let Err(error) = persist_session(&mut core) {
        if let Some(session) = core.unlocked.as_mut() {
            session.data = previous;
        }
        return Err(map_core_error(error));
    }
    mark_activity(&mut core);
    Ok(to_summary(&entry))
}

#[tauri::command]
fn update_entry(
    id: String,
    input: EntryInput,
    state: State<AppState>,
) -> CommandResult<EntrySummary> {
    if input.title.trim().is_empty() {
        return Err(CommandError::user_input("标题不能为空。"));
    }
    let mut core = lock_state(state.inner())?;
    let session = core.unlocked.as_mut().ok_or_else(CommandError::locked)?;
    let previous = session.data.clone();
    let Some(index) = session.data.entries.iter().position(|entry| entry.id == id) else {
        return Err(CommandError::user_input("找不到这条密码记录。"));
    };
    let entry = make_entry(&input, Some(&session.data.entries[index]));
    session.data.entries[index] = entry.clone();
    session.data.updated_at = now_string();
    if let Err(error) = persist_session(&mut core) {
        if let Some(session) = core.unlocked.as_mut() {
            session.data = previous;
        }
        return Err(map_core_error(error));
    }
    mark_activity(&mut core);
    Ok(to_summary(&entry))
}

#[tauri::command]
fn delete_entry(id: String, state: State<AppState>) -> CommandResult<()> {
    let mut core = lock_state(state.inner())?;
    let session = core.unlocked.as_mut().ok_or_else(CommandError::locked)?;
    let previous = session.data.clone();
    let old_len = session.data.entries.len();
    session.data.entries.retain(|entry| entry.id != id);
    if old_len == session.data.entries.len() {
        return Err(CommandError::user_input("找不到这条密码记录。"));
    }
    session.data.updated_at = now_string();
    if let Err(error) = persist_session(&mut core) {
        if let Some(session) = core.unlocked.as_mut() {
            session.data = previous;
        }
        return Err(map_core_error(error));
    }
    mark_activity(&mut core);
    Ok(())
}

#[tauri::command]
fn set_favorite(id: String, value: bool, state: State<AppState>) -> CommandResult<()> {
    let mut core = lock_state(state.inner())?;
    let session = core.unlocked.as_mut().ok_or_else(CommandError::locked)?;
    let previous = session.data.clone();
    let Some(entry) = session.data.entries.iter_mut().find(|entry| entry.id == id) else {
        return Err(CommandError::user_input("找不到这条密码记录。"));
    };
    entry.favorite = value;
    entry.updated_at = now_string();
    session.data.updated_at = now_string();
    if let Err(error) = persist_session(&mut core) {
        if let Some(session) = core.unlocked.as_mut() {
            session.data = previous;
        }
        return Err(map_core_error(error));
    }
    mark_activity(&mut core);
    Ok(())
}

#[tauri::command]
fn generate_password(options: PasswordGeneratorOptions) -> CommandResult<String> {
    if !(4..=128).contains(&options.length) {
        return Err(CommandError::user_input(
            "密码长度应在 4 到 128 个字符之间。",
        ));
    }
    let mut groups = Vec::new();
    if options.include_uppercase {
        groups.push("ABCDEFGHJKMNPQRSTUVWXYZ");
    }
    if options.include_lowercase {
        groups.push("abcdefghjkmnpqrstuvwxyz");
    }
    if options.include_numbers {
        groups.push("23456789");
    }
    if options.include_symbols {
        groups.push("!@#$%^&*()-_=+[]{}:,.?/|~");
    }
    if groups.is_empty() || groups.len() > options.length {
        return Err(CommandError::user_input(
            "请至少选择一种字符类型，并保证长度足够。",
        ));
    }
    let mut combined = String::new();
    for group in &groups {
        combined.push_str(group);
    }
    if !options.exclude_ambiguous {
        // The default groups already remove the most confusing glyphs.
        combined.push_str("O0oIl1");
    }
    let combined: Vec<char> = combined.chars().collect();
    let mut rng = OsRng;
    let mut result = Vec::with_capacity(options.length);
    for group in &groups {
        let chars: Vec<char> = group.chars().collect();
        result.push(chars[rng.gen_range(0..chars.len())]);
    }
    while result.len() < options.length {
        result.push(combined[rng.gen_range(0..combined.len())]);
    }
    result.shuffle(&mut rng);
    Ok(result.into_iter().collect())
}

#[tauri::command]
fn copy_sensitive_value(
    value: String,
    clear_after_seconds: Option<u64>,
    state: State<AppState>,
) -> CommandResult<ClipboardStatus> {
    let mut clipboard = Clipboard::new()
        .map_err(|_| CommandError::new("ClipboardError", "无法访问系统剪贴板，请稍后重试。"))?;
    clipboard
        .set_text(&value)
        .map_err(|_| CommandError::new("ClipboardError", "无法写入系统剪贴板，请稍后重试。"))?;
    let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
    let mut core = lock_state(state.inner())?;
    let seconds = clear_after_seconds
        .unwrap_or(core.settings.clipboard_clear_seconds)
        .clamp(5, 300);
    core.managed_clipboard.generation = core.managed_clipboard.generation.wrapping_add(1);
    let generation = core.managed_clipboard.generation;
    core.managed_clipboard.digest = Some(digest);
    mark_activity(&mut core);
    let state_for_timer = state.inner().clone();
    drop(core);
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));
        let Ok(mut core) = state_for_timer.0.lock() else {
            return;
        };
        if core.managed_clipboard.generation != generation {
            return;
        }
        if let Err(error) = clear_managed_clipboard_internal(&mut core) {
            eprintln!("[vaultroom] clipboard cleanup failed: {error}");
        }
    });
    Ok(ClipboardStatus {
        clear_after_seconds: seconds,
    })
}

#[tauri::command]
fn clear_managed_clipboard(state: State<AppState>) -> CommandResult<()> {
    let mut core = lock_state(state.inner())?;
    clear_managed_clipboard_internal(&mut core).map_err(map_core_error)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("could not resolve app data directory: {error}"))?;
            fs::create_dir_all(&app_data_dir)
                .map_err(|error| format!("could not create app data directory: {error}"))?;
            let state = AppState(Arc::new(Mutex::new(CoreState {
                app_data_dir: app_data_dir.clone(),
                vault_path: app_data_dir.join(DEFAULT_VAULT_FILE),
                settings: load_settings(&app_data_dir),
                unlocked: None,
                last_activity: Instant::now(),
                managed_clipboard: ManagedClipboard {
                    digest: None,
                    generation: 0,
                },
            })));
            app.manage(state.clone());
            start_auto_lock_worker(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_state,
            get_settings,
            set_settings,
            create_vault,
            open_vault,
            lock_vault,
            close_vault,
            record_activity,
            change_master_password,
            create_backup,
            export_vault,
            list_entries,
            get_entry,
            create_entry,
            update_entry,
            delete_entry,
            set_favorite,
            generate_password,
            copy_sensitive_value,
            clear_managed_clipboard,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Vaultroom application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    if let Ok(mut core) = state.0.lock() {
                        lock_vault_internal(&mut core);
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!("vaultroom-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create temp directory");
        path
    }

    #[test]
    fn vault_round_trip_and_wrong_password() {
        let dir = test_dir();
        let path = dir.join(DEFAULT_VAULT_FILE);
        let session =
            create_unlocked_vault(&path, "correct horse battery staple").expect("create vault");
        assert!(path.exists());
        let opened = open_vault_file(&path, "correct horse battery staple").expect("open vault");
        assert_eq!(opened.data.entries.len(), 0);
        assert_eq!(opened.dek, session.dek);
        assert!(matches!(
            open_vault_file(&path, "wrong password"),
            Err(CoreError::Authentication)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ciphertext_tampering_is_detected() {
        let dir = test_dir();
        let path = dir.join(DEFAULT_VAULT_FILE);
        create_unlocked_vault(&path, "a long test password").expect("create vault");
        let mut file = read_vault_container(&path).expect("read vault");
        let mut ciphertext = decode_bytes(&file.payload.ciphertext).expect("decode");
        ciphertext[0] ^= 0x55;
        file.payload.ciphertext = encode_bytes(&ciphertext);
        let bytes = serde_json::to_vec(&file).expect("encode");
        fs::write(&path, bytes).expect("tamper vault");
        assert!(matches!(
            open_vault_file(&path, "a long test password"),
            Err(CoreError::Authentication)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn password_generator_honors_selected_character_sets() {
        let password = generate_password(PasswordGeneratorOptions {
            length: 32,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
            exclude_ambiguous: true,
        })
        .expect("generate password");
        assert_eq!(password.len(), 32);
        assert!(password.chars().any(|value| value.is_ascii_uppercase()));
        assert!(password.chars().any(|value| value.is_ascii_lowercase()));
        assert!(password.chars().any(|value| value.is_ascii_digit()));
        assert!(password.chars().any(|value| !value.is_ascii_alphanumeric()));
        assert!(!password.chars().any(|value| "O0oIl1".contains(value)));
    }

    #[test]
    fn atomic_save_keeps_backup_of_previous_valid_file() {
        let dir = test_dir();
        let path = dir.join(DEFAULT_VAULT_FILE);
        let first = b"first vault";
        let second = b"second vault";
        write_bytes_atomically(&path, first, true).expect("write first");
        write_bytes_atomically(&path, second, true).expect("write second");
        assert_eq!(fs::read(&path).expect("read current"), second);
        assert_eq!(fs::read(backup_path(&path, 1)).expect("read backup"), first);
        let _ = fs::remove_dir_all(dir);
    }
}
