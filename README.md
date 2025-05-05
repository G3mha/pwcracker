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

## Data Sources

This project uses the following datasets for its dictionary and rainbow table attacks:

- [Bad Password Dataset](https://www.kaggle.com/datasets/kingabzpro/bad-password) - A collection of commonly used and leaked passwords from Kaggle, used for dictionary attacks and rainbow table generation.

For the generation of MD5 rainbow tables for testing, the project uses the online tool from [Unix4Lyfe](https://unix4lyfe.org/crypt/)

## Building the Project

### Prerequisites

- Docker (for building the project)
- CMake 3.22 or higher
- C compiler with C17 support
- OpenSSL development libraries
- Criterion testing framework (for tests)

### Build Commands

To run the project in a Docker container, use:

```bash
# Clone the repository
git clone
cd pwcracker
# Build the Docker image
docker-compose -f docker/docker-compose.yml up -d --remove-orphans
# Run the Docker container
docker-compose -f docker/docker-compose.yml run --rm pwcracker --usage
```

To load a file into the container, use:

```bash
docker cp $(pwd)/yourfile.txt password-hash-cracker_pwcracker_1:/app/data/
```

To build the project locally, follow these steps:

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

```code
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

```code
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

## Test files

The test files used in this project's unitary tests are generate using built-in commands from UNIX, like:

```sh
md5 -s "<salt><password>" # For MD5
```
