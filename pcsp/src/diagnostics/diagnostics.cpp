#include "pcsp/diagnostics.hpp"
#include <iostream>
#include <iomanip> 
#include <string>

// TODO(API Doc Sec 4.1): print each byte as two-digit lowercase hex,
// space-separated, prefixed by `label`.
void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (int i = 0; i < data.size(); i++) {
        if (i > 0) {
            std::cout << " ";
        }
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::setfill(' ') << "\n";
}
// TODO(REQ-DSP-301): print plaintext, cipher id (0x-prefixed hex), key
// length, and the ciphertext via print_hex(), before transmission.
void log_client_telemetry(const std::string& plaintext,
                           uint8_t cipher_id,
                           const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& ciphertext) {
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Cipher ID: 0x" << std::hex << std::setw(2) << std::setfill('0') 
              << (int)cipher_id << std::endl;
    // reset the hex stuff before printing length
    std::cout << std::dec << std::setfill(' ');
    std::cout << "Key length: " << key.size() << std::endl;   
    print_hex("Ciphertext", ciphertext);
}
// TODO(REQ-DSP-302): print, in order -- raw unresolved stream (print_hex),
// isolated ciphertext block (print_hex), recovered plaintext string.
void log_server_telemetry(const std::vector<uint8_t>& raw_stream,
                           const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& plaintext) {                 
    print_hex("Raw stream", raw_stream);
    print_hex("Ciphertext", ciphertext);
    std::cout << "Recovered plaintext: ";
    for (int i = 0; i < plaintext.size(); i++) {
        std::cout << (char)plaintext[i];
    }
    std::cout << std::endl;
}
