#include <iostream>
#include <stdexcept>
#include <bitset>
#include <algorithm>
#include <cstdint>
#include <random>
#include <fstream>
#include <queue>

using namespace std;

// forward declarations
uint32_t customHash(uint32_t num);
string iterativeHash(string key);
void crypt(bool encOrDec); // 0 = enc | 1 = dec
char Feistel(char x, string k, int rounds, bool encOrDec, int iteration);
string strXOR(string x, string y);
int main() {
  while (true) {
    string menChoiceProxy;
    cout << "Please choose a menu option below.\n";
    cout << "---------------------------------------------\n";
    cout << "1: Encrypt a file using a Feistel Network\n";
    cout << "2. Decrypt a file using a Feistel Network\n";
    cout << "3. Quit\n";
    cout << "---------------------------------------------\n";
    getline(cin, menChoiceProxy);
    int menChoice = menChoiceProxy[0] - '0';
    while (menChoice < 1 || menChoice > 3) {
      cout << "Invalid choice. Please choose a menu option below.\n";
      cout << "---------------------------------------------\n";
      cout << "1: Encrypt a file using a Feistel Network\n";
      cout << "2. Decrypt a file using a Feistel Network\n";
      cout << "3. Quit\n";
      cout << "---------------------------------------------\n";
      getline(cin, menChoiceProxy);
      menChoice = menChoiceProxy[0] - '0';
    }
    switch (menChoice) {
      case 1:
        crypt(0);
        break;
      case 2:
        crypt(1);
        break;
      case 3:
        cout << "Quitting...\n";
        return 0;
      default:
        cout << "Invalid input detected past catch. Halting...\n";
        return 0;
    }
  }
}

// crypt(bool encOrDec)
// PRE: User choose to enc/dec data.
// POST: Data enc/dec.
// WARNINGS: Not exception safe if file not found.
// STATUS: Completed, tested.
void crypt(bool encOrDec) {
  string path;
  string key;
  string line;
  string outfilename;
  if (encOrDec) {
    cout << "Please enter the path to the file you are trying to decrypt (include extension):\n";
    cout << "--------------------------------------------------------------------------------\n";
  } else {
    cout << "Please enter the path to the file you are trying to encrypt (include extension):\n";
    cout << "--------------------------------------------------------------------------------\n";
  }
  cin >> path;
  // ... rest of the function unchanged ...
}

// ... other functions follow ...
