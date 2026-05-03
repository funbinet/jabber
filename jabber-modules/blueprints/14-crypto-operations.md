# Cryptographic Operations — Category Blueprint

**Category:** `CRYPTO_OPERATIONS` | **Slug:** `crypto` | **Tools Dir:** `~/jabber/jabber-tools/crypto/`
**Package:** `com.jabber.jabber.modules.crypto` | **Group:** Operations & Assets

---

## ToolManager: `crypto/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `openssl` | `openssl` | system | `openssl version` | system |
| `gpg` | `gpg` | apt (gnupg) | `gpg --version` | `apt_install` |
| `age` | `age` | `FiloSottile/age` | `age --version` | `github_release` |
| `ccrypt` | `ccrypt` | apt | `ccrypt --version` | `apt_install` |
| `hashid` | `hashid` | pip | `hashid --help` | `pip_install` |

---

## Modules

## Standardized Infrastructure
Every module in this category MUST implement the following self-contained architecture, located in its own dedicated package (e.g., `com.jabber.jabber.modules.<category>.<module_name>/`):

- **`[ModuleName]Module.java`**: The primary controller that defines the `@JABBERModule` metadata, declares the `ModuleInputField` schemas for each execution mode, and handles the orchestration between the UI and the execution engine.
- **`[ModuleName]Engine.java`**: The core execution orchestrator that implements the mandatory 8-step execution doctrine. It manages the high-level logic, tool sequencing, and results aggregation.
- **`ToolManager.java`**: Registry for the 5+ required tools. Handles tool status checks, versioning, and automatic dependency installation via OS-specific package managers (apt, pip, github_release).
- **`InputSanitizer.java`**: Mode-aware validation logic that ensures all inputs (IPs, domains, file paths) are sanitized and conform to security best practices before process execution.
- **`ProcessExecutor.java`**: A thread-safe, low-level process runner that manages `ProcessBuilder` lifecycles, real-time stdout/stderr streaming, and timeout enforcement.
- **`CommandRecord.java`**: A structured data container that captures full telemetry for every command executed (CLI strings, exit codes, durations, and output previews) for the final report.
- **`ReportGenerator.java`**: The findings aggregator that transforms raw tool output and `CommandRecord` data into high-fidelity, structured reports in JSON, Markdown, and HTML formats. It is strictly responsible for capturing, organizing, and physically saving all generated outputs (files, payloads, artifacts) into the reporting structure.

---

## Execution Doctrine (MANDATORY - SURGICAL)

Every module MUST implement the following 8-step execution loop in its `[ModuleName]Engine.java`:

1.  **Validate Mode**: Verify that the selected `ModuleMode` is supported and available.
2.  **Sanitize Schema**: Validate and sanitize all user-provided inputs against the mode-specific schema using `InputSanitizer`.
    - **Failure**: If mandatory input is missing, return `[Input required for execution]`.
3.  **Target Intelligence**: Perform mandatory infrastructure discovery (DNS resolution, WHOIS lookup, server fingerprinting via `dnsx`, `subfinder`, `httpx`).
4.  **Tool Readiness & Verification**: Resolve binary paths via `ToolManager` AND verify the specific tools explicitly selected by the user for this execution.
    - **Failure**: If `selectedTools` list is empty, return `[Must select a tool for execution]`.
5.  **Surgical Command Orchestration**: Build the exact command strings and arguments ONLY for the external tools that were explicitly selected by the user via the frontend toggles.
    - If a tool is not selected, it MUST NOT execute.
    - If one tool is selected, only its command logic runs.
    - If multiple tools are selected, only those tools' commands run sequentially.
6.  **Real-Time Streaming**: Execute selected tools sequentially via `ProcessExecutor` and stream live stdout/stderr logs to the `TaskContext` for UI visibility.
7.  **Findings Extraction**: Parse raw tool output using `ReportGenerator` to identify and extract high-fidelity security findings.
    - **Anti-Pollution**: Findings MUST be flat and professional. Remove CLI strings and durations from executive finding reports.
8.  **Full Telemetry**: Aggregate all telemetry data into the final `ModuleResult` for complete auditability.

---

### Output & Transparency

- **NO Phantom Findings**: If a tool returns no data or an error, no finding is generated. Every result must be verified by real data.
- **Full Traceability**: Every report must include the exact CLI commands executed to ensure transparency and reproducibility.
- **Multi-Format Delivery**: Findings are generated simultaneously in JSON (for automation), HTML (for presentation), and Markdown (for documentation).

---

## Artifact & Output Generation Standard (J. Standard)
Every module in this category MUST physically create and preserve the following outputs:
- **Location**: `reports/artifacts/`, `reports/payloads/`, `reports/outputs/`, or `reports/analysis/` within the module workspace.
- **Naming**: `[Mode]_[Timestamp]_[OriginalName].[Ext]`
- **Hashing**: Mandatory SHA256 hashing for all generated files.
- **Reporting**: All files must be linked and accessible via the final `ReportGenerator` output.

---

## Frontend Requirements

Every module in the **Cryptographic Operations** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. General Crypto Ops
**ID:** `crypto-ops` | **Risk:** LOW | **File:** `CryptoOpsModule.java`
**Tools:** `openssl`, `gpg`, `age`, `ccrypt`, `hashid`

#### Execution Modes:

- **`ENCR`** (Short Name: `ENCR`)
    - **Purpose**: High-security symmetric encryption of sensitive files using multiple backends.
    - **Input Schema**: `{ input: Path, algorithm: String, key: String }`
    - **Multi-Tool Command Logic**:
        1. `openssl enc -<algorithm> -in <input> -out <input>.enc -pass pass:<key>` (Core OpenSSL)
        2. `gpg --symmetric --batch --passphrase <key> -o <input>.gpg <input>` (GPG Backup)
        3. `age -p -o <input>.age <input>` (Modern Age Encryption)
        4. `ccrypt -e -K <key> <input>` (Ccrypt Backend)
        5. `hashid <input>.enc` (Post-Encryption Validation)
    - **Execution Flow**: Core OpenSSL -> GPG Backup -> Age Modern -> Ccrypt Backend -> Validation.
    - **Output Generation & Artifacts**:
        - `reports/payloads/ENCRYPT_[Timestamp]_encrypted_file.enc`: Primary encrypted file generated via the selected backend.
        - `reports/artifacts/ENCRYPT_[Timestamp]_gpg_backup.gpg`: Symmetric GPG backup of the encrypted asset.
        - `reports/analysis/ENCRYPT_[Timestamp]_cipher_audit.json`: Detailed audit of the encryption algorithm and parameters.

- **`DECR`** (Short Name: `DECR`)
    - **Purpose**: Multi-backend decryption of symmetrically encrypted assets.
    - **Input Schema**: `{ input: Path, algorithm: String, key: String }`
    - **Multi-Tool Command Logic**:
        1. `openssl enc -d -<algorithm> -in <input> -out <input>.dec -pass pass:<key>` (Core OpenSSL)
        2. `gpg --decrypt --batch --passphrase <key> -o <input>.dec <input>` (GPG Decrypt)
        3. `age -d -o <input>.dec <input>` (Age Decrypt)
        4. `ccrypt -d -K <key> <input>` (Ccrypt Decrypt)
        5. `hashid <input>` (Cipher Identification)
    - **Execution Flow**: Core OpenSSL -> GPG Decrypt -> Age Decrypt -> Ccrypt Decrypt -> Cipher ID.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DECRYPT_[Timestamp]_decrypted_file.dec`: Successfully decrypted version of the input file.
        - `reports/artifacts/DECRYPT_[Timestamp]_decryption_log.txt`: Technical log of the multi-backend decryption attempt.
        - `reports/analysis/DECRYPT_[Timestamp]_cipher_id.json`: Identification of the cipher and encoding of the input asset.

---

### 2. AES Encryption Tool
**ID:** `crypto-aes` | **Risk:** LOW | **File:** `AESEncryptModule.java`
**Tools:** `openssl`, `ccrypt`, `gpg`, `python3`, `hashid`

#### Execution Modes:

- **`ENCR`** (Short Name: `ENCR`)
    - **Purpose**: AES-256-CBC hardening for cryptographic asset protection.
    - **Input Schema**: `{ input: Path, key: String }`
    - **Multi-Tool Command Logic**:
        1. `openssl enc -aes-256-cbc -salt -in <input> -out <input>.aes -k <key>` (Core AES Gen)
        2. `ccrypt -e -K <key> <input>` (Ccrypt Alternative)
        3. `gpg --symmetric --cipher-algo AES256 --passphrase <key> <input>` (GPG AES)
        4. `python3 -c "import hashlib; print(hashlib.sha256(b'<key>').hexdigest())"` (Key Integrity)
        5. `hashid <input>.aes` (Validation)
    - **Execution Flow**: Core AES -> Ccrypt Alternative -> GPG AES -> Key Integrity -> Validation.
    - **Output Generation & Artifacts**:
        - `reports/payloads/ENCRYPT_[Timestamp]_aes_hardened.aes`: AES-256-CBC hardened cryptographic asset.
        - `reports/artifacts/ENCRYPT_[Timestamp]_key_hash.txt`: SHA256 hash of the encryption key for integrity verification.
        - `reports/analysis/ENCRYPT_[Timestamp]_aes_validation.json`: Verification of the AES structure and salt handling.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Security audit of AES-encrypted files for entropy and structure.
    - **Input Schema**: `{ input: Path }`
    - **Multi-Tool Command Logic**:
        1. `hashid <input>` (Algorithm Detection)
        2. `openssl enc -aes-256-cbc -d -in <input> -pass pass:test` (Integrity Probe)
        3. `ccrypt --version` (Binary Audit)
        4. `gpg --version` (Binary Audit)
        5. `python3 --version` (Runtime Audit)
    - **Execution Flow**: Algorithm Detection -> Integrity Probe -> Binary Audit x2 -> Runtime Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_entropy_report.json`: Entropy and randomness analysis of the AES encrypted file.
        - `reports/artifacts/AUDIT_[Timestamp]_binary_integrity.json`: Status and version audit for all AES-related binaries.
        - `reports/analysis/AUDIT_[Timestamp]_integrity_probe.log`: Technical log of the OpenSSL integrity probe results.

---

### 3. RSA Key Generator
**ID:** `crypto-rsa` | **Risk:** LOW | **File:** `RSAKeyGenModule.java`
**Tools:** `openssl`, `ssh-keygen`, `gpg`, `python3`, `cat`

#### Execution Modes:

- **`GKEY`** (Short Name: `GKEY`)
    - **Purpose**: Generation of cryptographically strong RSA asymmetric key pairs.
    - **Input Schema**: `{ bits: int }`
    - **Multi-Tool Command Logic**:
        1. `openssl genrsa -out private.pem <bits>` (Core OpenSSL Gen)
        2. `ssh-keygen -t rsa -b <bits> -f ./id_rsa -N ""` (SSH-Keygen Gen)
        3. `gpg --batch --gen-key gpg_params` (GPG Key Gen)
        4. `python3 -c "from Crypto.PublicKey import RSA; print(RSA.generate(<bits>).export_key())"` (Python Gen)
        5. `cat private.pem` (Verification Disclosure)
    - **Execution Flow**: Core OpenSSL -> SSH-Keygen -> GPG Gen -> Python Gen -> Disclosure.
    - **Output Generation & Artifacts**:
        - `reports/payloads/GENKEY_[Timestamp]_private.pem`: Cryptographically strong RSA private key in PEM format.
        - `reports/artifacts/GENKEY_[Timestamp]_id_rsa`: Generated OpenSSH format RSA private key.
        - `reports/analysis/GENKEY_[Timestamp]_key_parameters.json`: Metadata on key bit length and generation entropy.

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Extraction and conversion of public components from RSA private keys.
    - **Input Schema**: `{ private_key: Path }`
    - **Multi-Tool Command Logic**:
        1. `openssl rsa -in <private_key> -pubout -out public.pem` (Core Extraction)
        2. `ssh-keygen -y -f <private_key> > public.ssh` (SSH Extraction)
        3. `gpg --export --armor > public.gpg` (GPG Export)
        4. `python3 -c "from Crypto.PublicKey import RSA; print(RSA.import_key(open('<private_key>').read()).publickey().export_key())"` (Python Extract)
        5. `cat public.pem` (Verification Disclosure)
    - **Execution Flow**: Core Extraction -> SSH Extraction -> GPG Export -> Python Extract -> Disclosure.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_public.pem`: Extracted RSA public key component in PEM format.
        - `reports/artifacts/EXTRACT_[Timestamp]_public.ssh`: Extracted public key in SSH-authorized_keys format.
        - `reports/analysis/EXTRACT_[Timestamp]_key_fingerprint.txt`: MD5 and SHA256 fingerprints of the extracted public key.

---

### 4. Hash Generator
**ID:** `crypto-hash` | **Risk:** LOW | **File:** `HashGenModule.java`
**Tools:** `openssl`, `sha256sum`, `md5sum`, `hashid`, `python3`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generation of cryptographic digests for data integrity verification.
    - **Input Schema**: `{ input: String, algorithm: String }`
    - **Multi-Tool Command Logic**:
        1. `echo -n "<input>" | openssl dgst -<algorithm>` (Core OpenSSL Digest)
        2. `echo -n "<input>" | sha256sum` (Native SHA256)
        3. `echo -n "<input>" | md5sum` (Native MD5)
        4. `python3 -c "import hashlib; print(hashlib.new('<algorithm>', b'<input>').hexdigest())"` (Python Digest)
        5. `hashid -m` (Mode Inventory)
    - **Execution Flow**: Core OpenSSL -> Native SHA256 -> Native MD5 -> Python Digest -> Mode Inventory.
    - **Output Generation & Artifacts**:
        - `reports/outputs/GEN_[Timestamp]_digest_results.json`: Map of generated cryptographic digests for the input data.
        - `reports/artifacts/GEN_[Timestamp]_openssl_dgst.txt`: Full output from the OpenSSL digest command.
        - `reports/analysis/GEN_[Timestamp]_algorithm_support.json`: Inventory of all digest algorithms supported by the current environment.

- **`DETC`** (Short Name: `DETC`)
    - **Purpose**: Automated identification of unknown hash types.
    - **Input Schema**: `{ hash: String }`
    - **Multi-Tool Command Logic**:
        1. `hashid <hash>` (Core Identification)
        2. `python3 -c "import hashid; ..."` (Alternative ID)
        3. `openssl dgst -h` (Support Audit)
        4. `sha256sum --version` (Binary Audit)
        5. `md5sum --version` (Binary Audit)
    - **Execution Flow**: Core Identification -> Alternative ID -> Support Audit -> Binary Audit x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DETECT_[Timestamp]_hash_identity.json`: Automated identification results for the unknown hash type.
        - `reports/artifacts/DETECT_[Timestamp]_hashid_output.txt`: Raw console output from the hashid identification tool.
        - `reports/analysis/DETECT_[Timestamp]_binary_readiness.json`: Verification of all hash detection and verification binaries.

---

### 5. Base64 Transformer
**ID:** `crypto-base64` | **Risk:** LOW | **File:** `Base64TxModule.java`
**Tools:** `base64`, `openssl`, `python3`, `xxd`, `sed`

#### Execution Modes:

- **`ENCD`** (Short Name: `ENCD`)
    - **Purpose**: Transform binary data or strings into Base64 ASCII representation for transmission.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `echo -n "<input>" | base64` (Core Base64 Encode)
        2. `echo -n "<input>" | openssl base64` (OpenSSL Encode)
        3. `python3 -c "import base64; print(base64.b64encode(b'<input>').decode())"` (Python Encode)
        4. `echo -n "<input>" | xxd -p | sed 's/../& /g'` (Hex Verification)
        5. `base64 --version` (Binary Audit)
    - **Execution Flow**: Core Encode -> OpenSSL Encode -> Python Encode -> Hex Verify -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENCODE_[Timestamp]_base64_encoded.txt`: Base64 ASCII representation of the input data.
        - `reports/artifacts/ENCODE_[Timestamp]_hex_verify.txt`: Hexadecimal verification of the input bytes before encoding.
        - `reports/analysis/ENCODE_[Timestamp]_binary_status.json`: Verification of the base64 and openssl binary status.

- **`DECD`** (Short Name: `DECD`)
    - **Purpose**: Restore original binary data or strings from Base64 ASCII representation.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `echo -n "<input>" | base64 -d` (Core Base64 Decode)
        2. `echo -n "<input>" | openssl base64 -d` (OpenSSL Decode)
        3. `python3 -c "import base64; print(base64.b64decode('<input>').decode())"` (Python Decode)
        4. `echo -n "<input>" | sed 's/ //g'` (Sanitization Audit)
        5. `xxd -r -p` (Hex-to-Binary Disclosure)
    - **Execution Flow**: Core Decode -> OpenSSL Decode -> Python Decode -> Sanitization -> Hex Disclosure.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DECODE_[Timestamp]_base64_decoded.bin`: Restored original binary data or string from Base64.
        - `reports/artifacts/DECODE_[Timestamp]_sanitization_log.txt`: Audit of the Base64 string for invalid characters.
        - `reports/analysis/DECODE_[Timestamp]_hex_disclosure.txt`: Hexadecimal representation of the decoded output for audit.

---

### 6. ROT13 Cipher
**ID:** `crypto-rot13` | **Risk:** LOW | **File:** `ROT13CryptModule.java`
**Tools:** `tr`, `python3`, `sed`, `awk`, `perl`

#### Execution Modes:

- **`ENCD`** (Short Name: `ENCD`)
    - **Purpose**: Apply ROT13 substitution cipher to a string for basic obfuscation.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `echo "<input>" | tr 'A-Za-z' 'N-ZA-Mn-za-m'` (Core TR Logic)
        2. `python3 -c "import codecs; print(codecs.encode('<input>', 'rot_13'))"` (Python Logic)
        3. `echo "<input>" | sed 'y/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM/'` (SED Logic)
        4. `perl -pe 'tr/A-Za-z/N-ZA-Mn-za-m/'` (Perl Logic)
        5. `awk '{print}'` (Buffer Pass-through)
    - **Execution Flow**: Core TR -> Python -> SED -> Perl -> Buffer Pass.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENCODE_[Timestamp]_rot13_result.txt`: String after application of the ROT13 substitution cipher.
        - `reports/artifacts/ENCODE_[Timestamp]_transformation_audit.json`: Verification of the character mapping for ROT13.
        - `reports/analysis/ENCODE_[Timestamp]_binary_readiness.json`: Verification of tr, python, sed, and perl status.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify ROT13 transformation integrity and character set handling.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `echo "ABC" | tr 'A-Za-z' 'N-ZA-Mn-za-m'` (Functionality Test)
        2. `python3 --version` (Binary Audit)
        3. `sed --version` (Binary Audit)
        4. `awk --version` (Binary Audit)
        5. `perl -v` (Binary Audit)
    - **Execution Flow**: Functionality Test -> Binary Audit x4.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_functional_test.json`: Results of the ROT13 character-space transformation test.
        - `reports/artifacts/AUDIT_[Timestamp]_tool_versions.json`: Version inventory for all text processing utilities.
        - `reports/analysis/AUDIT_[Timestamp]_charset_audit.txt`: Audit of character set handling and escape disclosure.

---

### 7. XOR Cipher
**ID:** `crypto-xor` | **Risk:** LOW | **File:** `XORCipherModule.java`
**Tools:** `python3`, `xxd`, `od`, `perl`, `sed`

#### Execution Modes:

- **`ENCR`** (Short Name: `ENCR`)
    - **Purpose**: Apply a symmetric XOR cipher with a repeating key to a file or stream.
    - **Input Schema**: `{ input: Path, key: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 -c "import sys; k='<key>'; sys.stdout.buffer.write(bytes([b ^ ord(k[i % len(k)]) for i, b in enumerate(sys.stdin.buffer.read())]))" < <input>` (Core XOR Logic)
        2. `perl -ne 'BEGIN{$k="<key>"} print $_ ^ $k x (length($_)/length($k) + 1)' < <input>` (Perl Alternative)
        3. `xxd -p <input>` (Hex Disclosure)
        4. `od -tx1 <input>` (Octal Audit)
        5. `sed -n 'l' <input>` (Escape Disclosure)
    - **Execution Flow**: Core XOR -> Perl Alternative -> Hex Disclosure -> Octal Audit -> Escape Disclosure.
    - **Output Generation & Artifacts**:
        - `reports/payloads/ENCRYPT_[Timestamp]_xor_encrypted.bin`: Symmetric XOR encrypted data artifact.
        - `reports/artifacts/ENCRYPT_[Timestamp]_hex_disclosure.txt`: Hexadecimal disclosure of the encrypted stream.
        - `reports/analysis/ENCRYPT_[Timestamp]_octal_audit.txt`: Octal-based audit of the input stream for non-printable characters.

- **`DECR`** (Short Name: `DECR`)
    - **Purpose**: Restore original data by re-applying the symmetric XOR key.
    - **Input Schema**: `{ input: Path, key: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 -c "import sys; k='<key>'; sys.stdout.buffer.write(bytes([b ^ ord(k[i % len(k)]) for i, b in enumerate(sys.stdin.buffer.read())]))" < <input>` (Core XOR Logic)
        2. `perl -ne 'BEGIN{$k="<key>"} print $_ ^ $k x (length($_)/length($k) + 1)' < <input>` (Perl Alternative)
        3. `xxd -r -p` (Hex Reconstruction)
        4. `od -c <input>` (Character Audit)
        5. `sed --version` (Binary Check)
    - **Execution Flow**: Core XOR -> Perl Alternative -> Hex Reconstruction -> Char Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DECRYPT_[Timestamp]_xor_decrypted.bin`: Successfully restored original data via symmetric XOR key.
        - `reports/artifacts/DECRYPT_[Timestamp]_hex_reconstruction.txt`: Reconstruction of the byte stream from hex for audit.
        - `reports/analysis/DECRYPT_[Timestamp]_binary_status.json`: Verification of python3 and perl runtime readiness.

---

### 8. Secure Communications
**ID:** `crypto-securecomm` | **Risk:** MEDIUM | **File:** `SecureCommModule.java`
**Tools:** `openssl`, `gpg`, `age`, `ssh`, `ncat`

#### Execution Modes:

- **`SRVR`** (Short Name: `SRVR`)
    - **Purpose**: Establish a secure SSL/TLS server listener for encrypted data reception.
    - **Input Schema**: `{ port: int, cert: Path, key: Path }`
    - **Multi-Tool Command Logic**:
        1. `openssl s_server -accept <port> -cert <cert> -key <key>` (Core SSL Server)
        2. `ncat -lvp <port> --ssl --ssl-cert <cert> --ssl-key <key>` (Ncat SSL Server)
        3. `ssh-keygen -l -f <cert>` (Cert Audit)
        4. `gpg --list-keys` (Identity Audit)
        5. `age --help` (Binary Check)
    - **Execution Flow**: Core SSL Server -> Ncat SSL Server -> Cert Audit -> Identity Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SERVER_[Timestamp]_ssl_server.log`: Execution log of the secure SSL/TLS server listener.
        - `reports/artifacts/SERVER_[Timestamp]_cert_audit.json`: Technical audit of the provided certificate and key.
        - `reports/analysis/SERVER_[Timestamp]_identity_inventory.json`: Inventory of available GPG and age identities on the host.

- **`CLNT`** (Short Name: `CLNT`)
    - **Purpose**: Connect to and verify the security posture of a remote SSL/TLS server.
    - **Input Schema**: `{ host: String, port: int }`
    - **Multi-Tool Command Logic**:
        1. `openssl s_client -connect <host>:<port> -showcerts` (Core SSL Client)
        2. `ncat --ssl <host> <port>` (Ncat SSL Client)
        3. `ssh -v -p <port> <host>` (SSH Probe)
        4. `gpg --version` (Binary Check)
        5. `age --version` (Binary Check)
    - **Execution Flow**: Core SSL Client -> Ncat SSL Client -> SSH Probe -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CLIENT_[Timestamp]_ssl_client.log`: Technical log of the SSL/TLS client connection attempt.
        - `reports/artifacts/CLIENT_[Timestamp]_server_certs.pem`: Captured server certificates from the remote connection.
        - `reports/analysis/CLIENT_[Timestamp]_security_probe.json`: Detailed report on the remote server's security posture and cipher support.

---
