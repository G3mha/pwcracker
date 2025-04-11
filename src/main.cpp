#include <iostream>
#include <vector>
#include <string>
#include "shadow_parser.h"
#include "attacks.h"


int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cout << "Usage: password-cracker <shadow-file> <attack-method>" << std::endl;
    std::cout << "Attack methods: dictionary, brute, rainbow" << std::endl;
    return 1;
  }

  std::vector<ShadowEntry> entries = parse_shadow_file(argv[1]);
  std::string attack_method = argv[2];
  
  if (attack_method == "dictionary") {
    DictionaryAttack attack("data/common_passwords.txt");
    benchmark_attack(entries, attack);
  } 
  else if (attack_method == "brute") {
    BruteForce attack(8, "abcdefghijklmnopqrstuvwxyz0123456789");
    benchmark_attack(entries, attack);
  }
  else if (attack_method == "rainbow") {
    RainbowTable table;
    // Demonstrate why rainbow tables fail against salted passwords
    benchmark_rainbow_attack(entries, table);
  }
  
  return 0;
}
