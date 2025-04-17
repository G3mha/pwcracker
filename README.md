# Password Hash Cracker

A security testing framework for password hashing techniques and cracking methods. This project is designed for educational purposes to demonstrate various password security concepts.

## Features

- **Multiple Attack Methods**:
  - Dictionary attacks using wordlists
  - Brute force attacks with configurable character sets
  - Rainbow table attacks for pre-computed hash lookups

- **Hash Algorithm Support**:
  - MD5 (`$1$` format)
  - SHA-256 (`$5$` format)
  - bcrypt (`$2a$` format)

- **Performance Features**:
  - Multi-threaded cracking
  - Configurable timeout
  - Benchmark mode for performance testing

- **Security Demonstrations**:
  - Sample shadow files of increasing difficulty
  - Demonstrations of salt effectiveness
  - Hash algorithm strength comparisons

## Building the Project

### Prerequisites

- CMake 3.22 or higher
- C compiler with C17 support
- OpenSSL development libraries
- Criterion testing framework (for tests)

### Build Commands

```bash
# Create a build directory
mkdir build && cd build

# Configure the project
cmake ..

# Build the project
make

# Run tests
make test

# Install the executable
sudo make install
```

## Usage

```
Usage: pwcracker [OPTION...] SHADOW_FILE
Password Hash Cracker -- A security testing framework for password hashing

  -b, --brute-force         Use brute force attack
  -c, --charset=CHARSET     Character set for brute force (default: abcdefghijklmnopqrstuvwxyz0123456789)
  -d, --dictionary=FILE     Use dictionary attack with specified wordlist
  -B, --benchmark           Run in benchmark mode
  -H, --hash-type=TYPE      Specify hash type (md5, sha256, bcrypt)
  -l, --max-length=LENGTH   Maximum password length for brute force (default: 8)
  -o, --output=FILE         Write results to FILE instead of standard output
  -q, --quiet               Don't produce any output
  -r, --rainbow=FILE        Use rainbow table attack with specified table
  -t, --threads=NUM         Number of threads to use (default: 1)
  -T, --timeout=SECONDS     Timeout in seconds (default: 0 - no timeout)
  -v, --verbose             Produce verbose output
  -?, --help                Give this help list
      --usage               Give a short usage message
  -V, --version             Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

### Examples

```bash
# Dictionary attack on easy shadow file
pwcracker -d data/common_passwords.txt data/easy_shadow.txt

# Brute force attack with limited character set
pwcracker -b -c abc123 -l 4 data/easy_shadow.txt

# Verbose dictionary attack with timing information
pwcracker -v -d data/common_passwords.txt data/medium_shadow.txt

# Multi-threaded attack with timeout
pwcracker -d data/common_passwords.txt -t 4 -T 30 data/hard_shadow.txt

# Benchmark hash functions
pwcracker -B
```

## Shadow File Format

The shadow files follow the standard Linux shadow file format:

```
username:$ID$SALT$HASH:UNUSED:FIELDS:CAN:BE:IGNORED
```

Where:
- `$ID$` identifies the hash algorithm:
  - `$1$` for MD5
  - `$5$` for SHA-256
  - `$2a$` for bcrypt
- `SALT` is the cryptographic salt
- `HASH` is the hashed password value

## Security Notice

This tool is intended for educational purposes and security research only. Usage against systems without explicit permission is illegal and unethical.

## License

This project is licensed under the AGPL License - see the LICENSE file for details.
