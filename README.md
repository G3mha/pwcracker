# Password Hash Cracker

A C-based framework for testing password security techniques and analyzing the effectiveness of different cracking methods.

## Overview

This educational tool demonstrates password security concepts by implementing:

- **Attack Methods**
  - Dictionary attacks
  - Brute force attacks  
  - Rainbow table attacks

- **Supported Hash Algorithms**
  - MD5 (`$1$` format)
  - SHA-256 (`$5$` format)
  - bcrypt (`$2a$` format)

To understand more about shadow files in the context of this project, go to [Shadow Files](./docs/shadow-files.md).

## Getting Started with VS Code Devcontainer

The project includes a devcontainer configuration for an isolated, reproducible development environment:

1. **Prerequisites**
   - [VS Code](https://code.visualstudio.com/)
   - [Docker](https://www.docker.com/)
   - [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

2. **Setup Steps**
   ```bash
   # Clone the repository
   git clone https://github.com/olincollege/password-hash-cracker.git
   cd password-hash-cracker
   
   # Open in VS Code
   code .
   
   # When prompted, click "Reopen in Container"
   # Or use Command Palette (F1): "Dev Containers: Reopen in Container"
   ```

3. **Building Inside Devcontainer**
   ```bash
   mkdir build && cd build
   cmake ..
   make clean; make
   ```

## Running Tests

The project includes comprehensive tests using the Criterion framework:

```bash
# In the build directory
ctest --output-on-failure

# To run specific test
./test/test_dictionary
./test/test_brute_force  
./test/test_rainbow_table
./test/test_cli
```

## Usage

The executable provides various options for password cracking:

```bash
# Dictionary attack example
./src/pwcracker -d ../data/test_pws.txt ../data/test_hashed_md5.txt

# Brute force attack with custom charset and length
./src/pwcracker -b -c "abc123" -l 4 ../data/test_hashed_md5.txt

# Rainbow table attack
./src/pwcracker -r ../data/test_rainbow_table.txt ../data/test_hashed_md5.txt

# Benchmark mode
./src/pwcracker -B

# Multi-threaded attack with timeout
./src/pwcracker -d ../data/test_pws.txt -t 4 -T 30 ../data/test_hashed_sha256.txt
```

### Command Options

```
-b, --brute-force         Use brute force attack
-c, --charset=CHARSET     Character set for brute force
-d, --dictionary=FILE     Use dictionary attack with specified wordlist
-B, --benchmark           Run in benchmark mode
-H, --hash-type=TYPE      Specify hash type (md5, sha256, bcrypt)
-l, --max-length=LENGTH   Maximum password length for brute force
-o, --output=FILE         Write results to FILE
-t, --threads=NUM         Number of threads to use
-T, --timeout=SECONDS     Timeout in seconds
-v, --verbose             Produce verbose output
```

## Test Data

The repository includes test data:
- `data/test_pws.txt`: Common passwords for dictionary attacks
- `data/test_hashed_md5.txt`: MD5-hashed passwords
- `data/test_hashed_sha256.txt`: SHA-256 hashed passwords
- `data/test_hashed_bcrypt.txt`: bcrypt hashed passwords
- `data/test_rainbow_table.txt`: Sample rainbow table

## Security Notice

This tool is intended for educational purposes and security research only. Usage against systems without explicit permission is illegal and unethical.

## License

This project is licensed under the AGPL License - see the LICENSE file for details.

## Test files

The test files used in this project's unitary tests are generate using built-in commands from UNIX, like:

```sh
md5 -s "<salt><password>" # For MD5
```
