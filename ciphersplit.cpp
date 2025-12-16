#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <chrono>

const size_t CHUNK_SIZE = 4096;
const size_t KEY_SIZE = 32;

bool SILENT_MODE = false;

struct Chunk {
    size_t id;
    size_t originalPos;
    std::vector<uint8_t> data;
};

// Simple SHA-256 implementation
class SHA256 {
private:
    uint32_t h[8];
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    
    static constexpr uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    
    uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
    
    void transform() {
        uint32_t m[64], a, b, c, d, e, f, g, h2, t1, t2;
        
        for (int i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
        for (int i = 16; i < 64; ++i)
            m[i] = gamma1(m[i - 2]) + m[i - 7] + gamma0(m[i - 15]) + m[i - 16];
        
        a = h[0]; b = h[1]; c = h[2]; d = h[3];
        e = h[4]; f = h[5]; g = h[6]; h2 = h[7];
        
        for (int i = 0; i < 64; ++i) {
            t1 = h2 + sig1(e) + ch(e, f, g) + k[i] + m[i];
            t2 = sig0(a) + maj(a, b, c);
            h2 = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h2;
    }
    
public:
    SHA256() { init(); }
    
    void init() {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
        datalen = 0; bitlen = 0;
    }
    
    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            this->data[datalen] = data[i];
            datalen++;
            if (datalen == 64) {
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }
    
    std::vector<uint8_t> finalize() {
        uint32_t i = datalen;
        data[i++] = 0x80;
        if (datalen < 56) {
            while (i < 56) data[i++] = 0x00;
        } else {
            while (i < 64) data[i++] = 0x00;
            transform();
            memset(data, 0, 56);
        }
        
        bitlen += datalen * 8;
        data[63] = bitlen; data[62] = bitlen >> 8; data[61] = bitlen >> 16; data[60] = bitlen >> 24;
        data[59] = bitlen >> 32; data[58] = bitlen >> 40; data[57] = bitlen >> 48; data[56] = bitlen >> 56;
        transform();
        
        std::vector<uint8_t> hash(32);
        for (int i = 0; i < 4; ++i) {
            hash[i]      = (h[0] >> (24 - i * 8)) & 0xff;
            hash[i + 4]  = (h[1] >> (24 - i * 8)) & 0xff;
            hash[i + 8]  = (h[2] >> (24 - i * 8)) & 0xff;
            hash[i + 12] = (h[3] >> (24 - i * 8)) & 0xff;
            hash[i + 16] = (h[4] >> (24 - i * 8)) & 0xff;
            hash[i + 20] = (h[5] >> (24 - i * 8)) & 0xff;
            hash[i + 24] = (h[6] >> (24 - i * 8)) & 0xff;
            hash[i + 28] = (h[7] >> (24 - i * 8)) & 0xff;
        }
        return hash;
    }
};

// Generate pseudo-random bytes using seed
std::vector<uint8_t> generatePRNG(size_t len, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<uint8_t> result(len);
    for (size_t i = 0; i < len; ++i) {
        result[i] = static_cast<uint8_t>(rng() & 0xFF);
    }
    return result;
}

// Derive key from passphrase
std::vector<uint8_t> deriveKey(const std::string& passphrase, const std::vector<uint8_t>& salt) {
    SHA256 sha;
    sha.update(reinterpret_cast<const uint8_t*>(passphrase.c_str()), passphrase.length());
    sha.update(salt.data(), salt.size());
    return sha.finalize();
}

// XOR-based stream cipher encryption/decryption
std::vector<uint8_t> encryptDecrypt(const std::vector<uint8_t>& data, 
                                     const std::vector<uint8_t>& key,
                                     uint64_t nonce) {
    SHA256 sha;
    sha.update(key.data(), key.size());
    uint8_t nonceBytes[8];
    for (int i = 0; i < 8; ++i) nonceBytes[i] = (nonce >> (i * 8)) & 0xFF;
    sha.update(nonceBytes, 8);
    std::vector<uint8_t> streamKey = sha.finalize();
    
    uint64_t seed = 0;
    for (int i = 0; i < 8; ++i) seed |= (uint64_t)streamKey[i] << (i * 8);
    
    std::vector<uint8_t> keystream = generatePRNG(data.size(), seed);
    std::vector<uint8_t> result(data.size());
    
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ keystream[i];
    }
    
    return result;
}

bool encryptFile(const std::string& inputFile, const std::string& outputFile,
                 const std::string& keyFile, const std::string& passphrase) {
    std::ifstream fin(inputFile, std::ios::binary);
    if (!fin) {
        std::cerr << "Cannot open input file\n";
        return false;
    }
    
    std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(fin)),
                                   std::istreambuf_iterator<char>());
    fin.close();
    
    std::reverse(fileData.begin(), fileData.end());
    
    // Generate random salt
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::vector<uint8_t> salt(16);
    for (auto& b : salt) b = static_cast<uint8_t>(rng() & 0xFF);
    
    std::vector<uint8_t> key = deriveKey(passphrase, salt);
    
    // Chunk the data
    std::vector<Chunk> chunks;
    size_t pos = 0;
    size_t chunkId = 0;
    
    while (pos < fileData.size()) {
        size_t remaining = fileData.size() - pos;
        size_t chunkLen = std::min(remaining, CHUNK_SIZE);
        
        Chunk chunk;
        chunk.id = chunkId++;
        chunk.originalPos = pos;
        chunk.data.assign(fileData.begin() + pos, fileData.begin() + pos + chunkLen);
        chunks.push_back(chunk);
        pos += chunkLen;
    }
    
    // Generate scramble order
    std::vector<size_t> scrambleOrder(chunks.size());
    std::iota(scrambleOrder.begin(), scrambleOrder.end(), 0);
    std::shuffle(scrambleOrder.begin(), scrambleOrder.end(), rng);
    
    // Encrypt each chunk with unique nonce
    std::vector<uint64_t> nonces;
    std::vector<std::vector<uint8_t>> encryptedChunks;
    
    for (auto& chunk : chunks) {
        uint64_t nonce = rng();
        nonces.push_back(nonce);
        
        std::vector<uint8_t> encrypted = encryptDecrypt(chunk.data, key, nonce);
        encryptedChunks.push_back(encrypted);
    }
    
    // Write encrypted file
    std::ofstream fout(outputFile, std::ios::binary);
    if (!fout) {
        std::cerr << "Cannot open output file\n";
        return false;
    }
    
    uint32_t chunkCount = chunks.size();
    fout.write(reinterpret_cast<const char*>(&chunkCount), sizeof(chunkCount));
    
    for (size_t i = 0; i < scrambleOrder.size(); ++i) {
        size_t idx = scrambleOrder[i];
        uint32_t originalId = chunks[idx].id;
        uint32_t dataLen = encryptedChunks[idx].size();
        uint64_t nonce = nonces[idx];
        
        fout.write(reinterpret_cast<const char*>(&originalId), sizeof(originalId));
        fout.write(reinterpret_cast<const char*>(&dataLen), sizeof(dataLen));
        fout.write(reinterpret_cast<const char*>(&nonce), sizeof(nonce));
        fout.write(reinterpret_cast<const char*>(encryptedChunks[idx].data()), dataLen);
    }
    fout.close();
    
    // Write key file
    std::ofstream fkey(keyFile, std::ios::binary);
    if (!fkey) {
        std::cerr << "Cannot create key file\n";
        return false;
    }
    
    fkey.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    fkey.write(reinterpret_cast<const char*>(&chunkCount), sizeof(chunkCount));
    for (const auto& chunk : chunks) {
        uint64_t id = chunk.id;
        uint64_t pos = chunk.originalPos;
        fkey.write(reinterpret_cast<const char*>(&id), sizeof(id));
        fkey.write(reinterpret_cast<const char*>(&pos), sizeof(pos));
    }
    fkey.close();
    
    std::cout << "Encryption successful!\n";
    std::cout << "Chunks: " << chunks.size() << "\n";
    return true;
}

bool decryptFile(const std::string& inputFile, const std::string& outputFile,
                 const std::string& keyFile, const std::string& passphrase) {
    // Read key file
    std::ifstream fkey(keyFile, std::ios::binary);
    if (!fkey) {
        std::cerr << "Cannot open key file\n";
        return false;
    }
    
    std::vector<uint8_t> salt(16);
    fkey.read(reinterpret_cast<char*>(salt.data()), salt.size());
    
    uint32_t chunkCount;
    fkey.read(reinterpret_cast<char*>(&chunkCount), sizeof(chunkCount));
    
    std::vector<std::pair<uint64_t, uint64_t>> chunkMap;
    for (uint32_t i = 0; i < chunkCount; ++i) {
        uint64_t id, pos;
        fkey.read(reinterpret_cast<char*>(&id), sizeof(id));
        fkey.read(reinterpret_cast<char*>(&pos), sizeof(pos));
        chunkMap.push_back({id, pos});
    }
    fkey.close();
    
    std::vector<uint8_t> key = deriveKey(passphrase, salt);
    
    // Read encrypted file
    std::ifstream fin(inputFile, std::ios::binary);
    if (!fin) {
        std::cerr << "Cannot open encrypted file\n";
        return false;
    }
    
    uint32_t fileChunkCount;
    fin.read(reinterpret_cast<char*>(&fileChunkCount), sizeof(fileChunkCount));
    
    if (fileChunkCount != chunkCount) {
        std::cerr << "Chunk count mismatch!\n";
        return false;
    }
    
    std::vector<Chunk> decryptedChunks(chunkCount);
    
    for (uint32_t i = 0; i < chunkCount; ++i) {
        uint32_t originalId, dataLen;
        uint64_t nonce;
        fin.read(reinterpret_cast<char*>(&originalId), sizeof(originalId));
        fin.read(reinterpret_cast<char*>(&dataLen), sizeof(dataLen));
        fin.read(reinterpret_cast<char*>(&nonce), sizeof(nonce));
        
        std::vector<uint8_t> encData(dataLen);
        fin.read(reinterpret_cast<char*>(encData.data()), dataLen);
        
        std::vector<uint8_t> decData = encryptDecrypt(encData, key, nonce);
        
        decryptedChunks[originalId].id = originalId;
        decryptedChunks[originalId].originalPos = chunkMap[originalId].second;
        decryptedChunks[originalId].data = decData;
    }
    fin.close();
    
    // Sort by original position
    std::sort(decryptedChunks.begin(), decryptedChunks.end(),
              [](const Chunk& a, const Chunk& b) { return a.originalPos < b.originalPos; });
    
    // Reconstruct file
    std::vector<uint8_t> fileData;
    for (const auto& chunk : decryptedChunks) {
        fileData.insert(fileData.end(), chunk.data.begin(), chunk.data.end());
    }
    
    std::reverse(fileData.begin(), fileData.end());
    
    // Write output
    std::ofstream fout(outputFile, std::ios::binary);
    if (!fout) {
        std::cerr << "Cannot create output file\n";
        return false;
    }
    fout.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
    fout.close();
    
    std::cout << "Decryption successful!\n";
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "  Encrypt: " << argv[0] << " -e <input> <output> <keyfile> <passphrase>\n";
        std::cout << "  Decrypt: " << argv[0] << " -d <encrypted> <output> <keyfile> <passphrase>\n";
        return 1;
    }
    
    std::string mode = argv[1];
    
    if (mode == "-e" && argc == 6) {
        return encryptFile(argv[2], argv[3], argv[4], argv[5]) ? 0 : 1;
    } else if (mode == "-d" && argc == 6) {
        return decryptFile(argv[2], argv[3], argv[4], argv[5]) ? 0 : 1;
    } else {
        std::cerr << "Invalid arguments\n";
        return 1;
    }
}
