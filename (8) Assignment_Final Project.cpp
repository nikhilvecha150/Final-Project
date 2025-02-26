#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <fstream>
#include <cstdint>

using namespace std;

// SHA-256 constant values
const uint32_t k_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
};

//  Perform right bitwise rotation
uint32_t right_rotate(uint32_t value, unsigned int shift_bit_s) {
    return (value >> shift_bit_s) | (value << (32 - shift_bit_s));
}

// Function to calculate SHA-256 hash
string compute_sha256(const string &input_txt_1) {
    // Initial hash values for SHA-256 algo
    uint32_t hash_val_a[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Input text into a byte array
    vector<uint8_t> message_buffer_aa(input_txt_1.begin(), input_txt_1.end());
    uint64_t original_bit_length_s = message_buffer_aa.size() * 8; // Save original length before padding

    // Append "1" bit (0x80 in hex) as per SHA-256 padding rules
    message_buffer_aa.push_back(0x80);

    // Add enough zero padding until the message length is 448 mod 512
    while ((message_buffer_aa.size() * 8) % 512 != 448) {
        message_buffer_aa.push_back(0x00);
    }

    // Append the original message length as 64-bit integer
    for (int varr_i = 7; varr_i >= 0; varr_i--) {
        message_buffer_aa.push_back((original_bit_length_s >> (varr_i * 8)) & 0xFF);
    }

    // Process message in 512-bit (64-byte) chunks
    for (size_t chunk_strt_a = 0; chunk_strt_a < message_buffer_aa.size(); chunk_strt_a += 64) {
        uint32_t words[64] = {0};

        // First 16 words are from the message chunk
        for (int varr_j = 0; varr_j < 16; varr_j++) {
            words[varr_j] = (message_buffer_aa[chunk_strt_a + varr_j * 4] << 24) |
                       (message_buffer_aa[chunk_strt_a + varr_j * 4 + 1] << 16) |
                       (message_buffer_aa[chunk_strt_a + varr_j * 4 + 2] << 8) |
                       (message_buffer_aa[chunk_strt_a + varr_j * 4 + 3]);
        }

        // Expand the 16 words into the remaining 48words
        for (int itrr_j = 16; itrr_j < 64; itrr_j++) {
            uint32_t s0 = right_rotate(words[itrr_j - 15], 7) ^ right_rotate(words[itrr_j - 15], 18) ^ (words[itrr_j - 15] >> 3);
            uint32_t s1 = right_rotate(words[itrr_j - 2], 17) ^ right_rotate(words[itrr_j - 2], 19) ^ (words[itrr_j - 2] >> 10);
            words[itrr_j] = words[itrr_j - 16] + s0 + words[itrr_j - 7] + s1;
        }

        // Working variables with current hash values
        uint32_t a = hash_val_a[0], b = hash_val_a[1], c = hash_val_a[2], d = hash_val_a[3];
        uint32_t e = hash_val_a[4], f = hash_val_a[5], g = hash_val_a[6], h = hash_val_a[7];

        // Perform the 64 SHA-256
        for (int varr_jb = 0; varr_jb < 64; varr_jb++) {
            uint32_t s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
            uint32_t choice = (e & f) ^ (~e & g);
            uint32_t temp1 = h + s1 + choice + k_constants[varr_jb] + words[varr_jb];

            uint32_t s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
            uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + majority;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Update the hash values
        hash_val_a[0] += a;
        hash_val_a[1] += b;
        hash_val_a[2] += c;
        hash_val_a[3] += d;
        hash_val_a[4] += e;
        hash_val_a[5] += f;
        hash_val_a[6] += g;
        hash_val_a[7] += h;
    }

    // Convert hash values to a hexadecimal string
    stringstream hash_outt;
    for (int itr_i = 0; itr_i < 8; itr_i++) {
        hash_outt << hex << setw(8) << setfill('0') << hash_val_a[itr_i];
    }
    return hash_outt.str();
}

// Function to read a text file and return its contents
string read_file(const string &file_name_1) {
    ifstream input_file(file_name_1);

    if (!input_file) {
        cerr << "Error: Could not open file '" << file_name_1 << "'!" << endl;
        return "";
    }

    stringstream bufffer;
    bufffer << input_file.rdbuf();
    return bufffer.str();
}

// Function to execute SHA-256
int main() {
    string file_nme = "mark.txt";

    // Read the contents of mark.txt
    string book_txt = read_file(file_nme);
    if (book_txt.empty()) {
        return 1;
    }

    // Compute hash of the extracted text
    string sha256_hash_result = compute_sha256(book_txt);

    // The final hash
    cout << "SHA-256 Hash of the Book of Mark: " << sha256_hash_result << endl;

    return 0;
}
