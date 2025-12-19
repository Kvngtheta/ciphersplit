# CipherSplit - File/Directory Encryption with Chunking & Scrambling

A secure file and directory encryption tool that reverses, chunks, encrypts, and scrambles your files. Supports recursive directory encryption. No external dependencies required - uses only standard C++17.

## Features

- Content Reversal - Entire file is reversed before processing
- Chunking - Splits data into 4KB chunks (configurable)
- Strong Encryption - Custom SHA-256 based stream cipher
- Scrambling - Chunks are randomly reordered
- Dual-File Security - Requires both encrypted file AND key file
- Passphrase Protection - SHA-256 key derivation with random salt
- Fully Reversible - Perfect reconstruction of original file
- Directory Support - Recursively encrypt/decrypt entire folder structures
- Secure Deletion - Delete or shred original files after encryption
- Custom Splash Screens - Personalize the interface
- Silent Mode - Optional flag to suppress all output

## Security Model

Your data is protected by **three security layers**:

1. Passphrase - Encrypts each individual chunk
2. Key File - Contains the scramble mapping (which chunk goes where)
3. Encrypted File - The scrambled, encrypted chunks

An attacker needs **all three** to recover your data:
- Encrypted `.bin` file
- Key `.key` file  
- Your passphrase

## Installation

### Requirements
- C++17 compatible compiler (GCC, Clang, MSVC)
- No external libraries needed!

### Compilation

**Linux/Mac:**
```bash
g++ -o ciphersplit ciphersplit.cpp -std=c++17
```

**Windows (MinGW):**
```bash
g++ -o ciphersplit.exe ciphersplit.cpp -std=c++17
```

**Windows (Visual Studio):**
```bash
cl /EHsc /std:c++17 ciphersplit.cpp
```

## Usage

### Encrypt a Single File

```bash
./ciphersplit -e <input_file> <output_encrypted> <output_keyfile> <passphrase> [--silent]
```

**Example:**
```bash
./ciphersplit -e secret.txt encrypted.bin keyfile.key "MySecurePassword123"
```

**With silent mode:**
```bash
./ciphersplit -e secret.txt encrypted.bin keyfile.key "MySecurePassword123" --silent
```

**Output:**
- `encrypted.bin` - Your encrypted, scrambled data
- `keyfile.key` - The key file needed for decryption

### Decrypt a Single File

```bash
./ciphersplit -d <encrypted_file> <output_file> <keyfile> <passphrase> [--silent]
```

**Example:**
```bash
./ciphersplit -d encrypted.bin recovered.txt keyfile.key "MySecurePassword123"
```

**Output:**
- `recovered.txt` - Your original file, perfectly restored

### Encrypt an Entire Directory

```bash
./ciphersplit -E <input_directory> <output_directory> <passphrase> [--silent]
```

**Example:**
```bash
./ciphersplit -E ~/Documents/sensitive ~/Encrypted/backup "MySecurePassword123"
```

**Output:**
- Creates `output_directory` containing:
  - `file_0.bin`, `file_0.key` - First file encrypted
  - `file_1.bin`, `file_1.key` - Second file encrypted
  - `file_N.bin`, `file_N.key` - Nth file encrypted
  - `directory.idx` - Master index mapping original paths to encrypted files

### Decrypt an Entire Directory

```bash
./ciphersplit -D <encrypted_directory> <output_directory> <passphrase> [--silent]
```

**Example:**
```bash
./ciphersplit -D ~/Encrypted/backup ~/Documents/restored "MySecurePassword123"
```

**Output:**
- Recreates original directory structure in `output_directory`
- All files decrypted to their original names and locations

## Secure Deletion Options

### Delete Originals After Encryption

```bash
./ciphersplit -e secret.txt encrypted.bin key.key "pass" --delete
```

**What it does:**
- Encrypts the file
- Deletes the original file immediately after successful encryption
- Fast deletion (standard filesystem delete)

### Securely Shred Originals After Encryption

```bash
./ciphersplit -e secret.txt encrypted.bin key.key "pass" --shred
```

**What it does:**
- Encrypts the file
- Overwrites original with random data (3 passes)
- Makes data recovery virtually impossible
- Slower but much more secure

### Directory Mode with Shredding

```bash
./ciphersplit -E ~/Documents ~/Encrypted "pass" --shred
```

**What it does:**
- Encrypts all files in directory
- Shreds each original file after encryption
- Removes entire original directory structure

## Splash Screen Customization

### Disable Splash Screen

```bash
./ciphersplit -e file.txt enc.bin key.key "pass" --no-splash
```

### Use Custom Splash Screen

```bash
./ciphersplit -e file.txt enc.bin key.key "pass" --splash mysplash.txt
```

Create `mysplash.txt` with your own ASCII art:
```
  ╔═══════════════════════════╗
  ║   MY CUSTOM ENCRYPTOR     ║
  ║   Protect Your Data       ║
  ╚═══════════════════════════╝
```

## How It Works

### Single File Encryption Process

1. Read - Loads your input file into memory
2. Reverse - Reverses entire file content (backwards)
3. Chunk - Splits into 4KB chunks, each labeled with ID and position
4. Salt - Generates random 16-byte salt
5. Derive Key - SHA-256(passphrase + salt) = encryption key
6. Encrypt - Each chunk encrypted with unique nonce
7. Scramble - Chunks shuffled into random order
8. Write - Saves scrambled chunks to `.bin` file
9. Save Key - Writes salt and chunk mapping to `.key` file

### Single File Decryption Process

1. Read Key File - Loads salt and chunk mapping
2. Derive Key - SHA-256(passphrase + salt) = encryption key
3. Read Encrypted File - Loads all scrambled chunks
4. Decrypt - Each chunk decrypted with its nonce
5. Unscramble - Chunks sorted back to original positions using mapping
6. Reassemble - Chunks concatenated in correct order
7. Reverse - Content reversed back to original
8. Write - Saves recovered file

### Directory Encryption Process

1. Scan - Recursively finds all files in directory tree
2. Enumerate - Assigns each file a sequential ID (file_0, file_1, etc.)
3. Encrypt Each - Each file encrypted individually with its own .bin and .key files
4. Index - Creates `directory.idx` mapping original paths to encrypted filenames
5. Preserve Structure - Original directory hierarchy stored in index

### Directory Decryption Process

1. Read Index - Loads `directory.idx` to get file mappings
2. Recreate Structure - Creates original directory tree
3. Decrypt Each - Each .bin/.key pair decrypted to original location
4. Restore Names - Files restored with original names and paths

## File Format Specifications

### Encrypted File (.bin)

```
[4 bytes]  Chunk count
[For each chunk:]
  [4 bytes]  Original chunk ID
  [4 bytes]  Encrypted data length
  [8 bytes]  Nonce (encryption IV)
  [N bytes]  Encrypted chunk data
```

### Key File (.key)

```
[16 bytes] Salt
[4 bytes]  Chunk count
[For each chunk:]
  [8 bytes]  Chunk ID
  [8 bytes]  Original position in file
```

### Directory Index File (directory.idx)

```
[Text file format, one line per file:]
original/path/to/file.txt|file_0.bin
another/path/document.pdf|file_1.bin
subdirectory/image.jpg|file_2.bin
```

## Security Features

### Strong Encryption
- SHA-256 for key derivation
- Unique nonce per chunk prevents pattern analysis
- Stream cipher based on cryptographic PRNG

### Random Salt
- 16-byte random salt generated per encryption
- Same passphrase produces different encrypted files each time
- Prevents rainbow table attacks

### Scrambling
- Cryptographically secure random shuffle
- Without key file, chunk order is unrecoverable
- Adds layer of confusion even if encryption is broken

### Content Reversal
- Additional obfuscation layer
- File signatures and headers become unrecognizable

### Secure Deletion
- --delete: Standard filesystem deletion
- --shred: 3-pass random overwrite before deletion
  - Pass 1: Random data overwrite
  - Pass 2: Random data overwrite
  - Pass 3: Random data overwrite
  - Final: Filesystem deletion
- Makes forensic recovery extremely difficult

## Best Practices

### Storage
- Separate locations - Store `.bin` and `.key` files in different places
- Backup key file - Without it, your data is unrecoverable
- Strong passphrase - Use 12+ characters with mixed case, numbers, symbols

### Passphrase Tips
Good: `MyC0mpl3x!Passw0rd#2024`
Bad: `password123`

### What to Do
- Test decrypt immediately after encrypting
- Keep multiple backups of key file
- Use a password manager for passphrases
- Verify file integrity after encryption
- Use --shred for truly sensitive data (slower but secure)
- Test recovery before deleting/shredding originals on important data

### What NOT to Do
- Don't lose your key file (unrecoverable!)
- Don't forget your passphrase (unrecoverable!)
- Don't store `.bin` and `.key` together (reduces security)
- Don't use weak passphrases
- Don't use --delete or --shred until you've verified encryption works
- Don't use --shred on mechanical hard drives repeatedly (wear)

## Examples

### Basic File Encryption
```bash
# Encrypt a document
./ciphersplit -e document.pdf encrypted.bin key.key "StrongPass123!"

# Verify it worked
./ciphersplit -d encrypted.bin test.pdf key.key "StrongPass123!"
```

### Encrypt and Delete Original
```bash
# Fast delete
./ciphersplit -e sensitive.doc encrypted.bin key.key "pass" --delete

# Secure shred (recommended for sensitive data)
./ciphersplit -e topsecret.pdf encrypted.bin key.key "pass" --shred
```

### Directory Encryption with Shredding
```bash
# Encrypt entire project folder and securely remove originals
./ciphersplit -E ~/Projects/MyApp ~/Backup/MyApp_encrypted "SecurePass2024" --shred

# Later, decrypt it back
./ciphersplit -D ~/Backup/MyApp_encrypted ~/Projects/MyApp_restored "SecurePass2024"
```

### Custom Splash Screen
```bash
# Create your splash file
cat > company_splash.txt << 'EOF'
  ================================
      ACME Corp Secure Vault
      Protecting Your Assets
  ================================
EOF

# Use it
./ciphersplit -e data.xlsx enc.bin key.key "pass" --splash company_splash.txt
```

### Backup Strategy with Directory Mode
```bash
# Encrypt sensitive documents and shred originals
./ciphersplit -E ~/Documents/Tax_Returns ~/Encrypted/Taxes_2024 "MyTaxPassword" --shred

# Copy encrypted folder to cloud storage (safe, originals are gone)
cp -r ~/Encrypted/Taxes_2024 ~/Dropbox/Backups/

# Store passphrase separately (password manager)

# Later, restore from cloud
./ciphersplit -D ~/Dropbox/Backups/Taxes_2024 ~/Restored/Tax_Returns "MyTaxPassword"
```

### Silent Mode for Scripts
```bash
# No output - useful for automation
./ciphersplit -e data.txt encrypted.bin key.key "MyPass" --silent --delete
echo $?  # Check exit code: 0 = success, 1 = failure

# Silent directory encryption with shredding
./ciphersplit -E ~/data ~/encrypted "pass" --silent --shred && echo "Done" || echo "Failed"
```

### Combining Options
```bash
# Encrypt, shred, no splash, silent mode
./ciphersplit -e secret.txt enc.bin key.key "pass" --shred --no-splash --silent

# Directory mode with all options
./ciphersplit -E ~/folder ~/encrypted "pass" --shred --silent
```

### Secure Storage Strategy
```bash
# Encrypt file
./ciphersplit -e sensitive.txt encrypted.bin local.key "MyPassword"

# Store encrypted file locally
mv encrypted.bin ~/Documents/

# Backup key file to USB drive
cp local.key /media/usb/backup.key

# Also backup key to cloud (encrypted separately if needed)
cp local.key ~/Dropbox/backup.key
```

### Wrong Passphrase
```bash
# This will produce garbage output
./ciphersplit -d encrypted.bin wrong.txt key.key "WrongPassword"
# File decrypts but content is random garbage
```

## Troubleshooting

### "Cannot open input file"
- Check file exists and path is correct
- Verify you have read permissions

### "Cannot open output file"
- Check you have write permissions in directory
- Ensure output path is valid

### "Chunk count mismatch"
- Wrong key file for this encrypted file
- File may be corrupted

### Decrypted file is garbage
- Wrong passphrase used
- Key file doesn't match encrypted file
- Files may be corrupted

### Directory decryption fails
- Missing or corrupted `directory.idx` file
- Wrong passphrase
- Missing .bin or .key files

### Original files not deleted
- Encryption failed (files preserved for safety)
- Insufficient permissions to delete
- Check return code and error messages

### Shredding is slow
- Shredding overwrites files 3 times with random data
- This is intentional for security
- Use --delete for faster (but less secure) removal

### Compilation errors
- Ensure C++17 support: add `-std=c++17` flag
- Check compiler version is recent enough
- Ensure `<filesystem>` header is available (GCC 8+, Clang 7+, MSVC 2017+)

## Technical Details

### Cryptography
- Hash Function: SHA-256 (full implementation)
- Key Derivation: SHA-256(passphrase || salt)
- Encryption: Stream cipher using SHA-256 seeded PRNG
- Nonce: 64-bit unique per chunk

### Performance
- Memory Usage: Loads entire file into memory (single file mode)
- Directory Mode: Processes one file at a time (memory efficient)
- Speed: ~50-100 MB/s per file (varies by system)
- Chunk Size: 4096 bytes (configurable in source)

### Limitations
- Single file mode: File must fit in available RAM
- Not suitable for files larger than available memory in single file mode
- No streaming mode for single files (processes entire file at once)
- Directory mode has no size limitations (processes one file at a time)

## Customization

### Change Chunk Size
Edit `CHUNK_SIZE` constant in source code:
```cpp
const size_t CHUNK_SIZE = 8192;  // Change to 8KB chunks
```

### Adjust Key Size
Edit `KEY_SIZE` constant:
```cpp
const size_t KEY_SIZE = 32;  // 256-bit (don't change unless you know why)
```

## License

This software is provided as-is for educational and personal use.

## Warnings

IMPORTANT: 
- This is custom cryptography for educational purposes
- For production use, consider established libraries like libsodium or OpenSSL
- No warranty - test thoroughly before trusting with critical data
- Losing your key file or passphrase means permanent data loss
- Keep backups of both encrypted files AND key files

## Support

For issues, questions, or improvements:
- Review the code comments
- Test with non-critical files first
- Keep backups of original files until verified

## Version

Version: 2.0  
Date: December 2025

Language: C++17

## Changelog

Version 2.0:
- Added full directory encryption/decryption support
- Recursive directory traversal
- Directory structure preservation
- Individual file encryption in directory mode
- Master index file for directory mapping
- Added --delete flag for removing originals after encryption
- Added --shred flag for secure 3-pass overwrite deletion
- Added custom splash screen support (--splash)
- Added --no-splash flag to disable splash screen
- Improved error handling for file operations

Version 1.0:
- Initial release
- Single file encryption/decryption
- Chunking and scrambling
- Silent mode
