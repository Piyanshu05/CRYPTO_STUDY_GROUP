#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "pcsp/diagnostics.hpp"

using namespace std; 

int main() {
    streambuf* original_cout = cout.rdbuf();
    ostringstream capture;
    
    // TEST 1: print_hex
    cout.rdbuf(capture.rdbuf());
    
    vector<uint8_t> data1 = {0x00, 0x0a, 0xff};
    print_hex("Label", data1);
    
    string actual1 = capture.str();
    string expected1 = "Label: 00 0a ff\n";
    
    cout.rdbuf(original_cout); 
    if (actual1 != expected1) {
        cout << "print_hex mismatch!\n";
        cout << "Expected:\n" << expected1;
        cout << "Actual:\n" << actual1;
        return 1;
    }

    // TEST 2: log_client_telemetry
    capture.str(""); 
    capture.clear();
    
    cout.rdbuf(capture.rdbuf()); 
    
    vector<uint8_t> key = {0x01, 0x02};
    vector<uint8_t> cipher = {0x00, 0x0f, 0xa5};
    log_client_telemetry("HELLO", 0x2a, key, cipher);
    
    string actual2 = capture.str();
    string expected2 = "Plaintext: HELLO\nCipher ID: 0x2a\nKey length: 2\nCiphertext: 00 0f a5\n";
    
    cout.rdbuf(original_cout);
    if (actual2 != expected2) {
        cout << "log_client_telemetry mismatch!\n";
        cout << "Expected:\n" << expected2;
        cout << "Actual:\n" << actual2;
        return 1;
    }

    // TEST 3: log_server_telemetry
    
    capture.str(""); 
    capture.clear();
    
    cout.rdbuf(capture.rdbuf());
    
    vector<uint8_t> stream = {0x01, 0x02};
    vector<uint8_t> ciph2 = {0x0a};
    vector<uint8_t> pt = {'O', 'K'}; 
    
    log_server_telemetry(stream, ciph2, pt);
    
    string actual3 = capture.str();
    string expected3 = "Raw stream: 01 02\nCiphertext: 0a\nRecovered plaintext: OK\n";
    
    cout.rdbuf(original_cout);
    if (actual3 != expected3) {
        cout << "log_server_telemetry mismatch!\n";
        cout << "Expected:\n" << expected3;
        cout << "Actual:\n" << actual3;
        return 1;
    }

    cout << "All diagnostic tests passed successfully!" << endl;
    return 0;
}