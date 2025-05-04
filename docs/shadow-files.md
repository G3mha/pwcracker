# Shadow File Samples

## What is a shadow file?

A shadow file is a file that contains the hashed passwords of all the users on a system. It is used by the `shadow` command to check the passwords of users.

## What are the samples?

Our project includes three sample shadow files with increasing security levels:

### 1. Easy Shadow File (MD5)

- Uses `$1$` prefix indicating MD5 hashing algorithm
- MD5 is considered cryptographically broken
- Extremely fast to compute (billions of hashes per second on modern hardware)
- Vulnerable to rainbow table attacks
- Can be cracked in seconds to minutes with dictionary attacks

### 2. Medium Shadow File (SHA-256)

- Uses `$5$` prefix indicating SHA-256 hashing algorithm
- More secure than MD5 but still vulnerable to brute force
- Approximately 10-20 times slower to compute than MD5
- Better resistance to rainbow tables when properly salted
- Can be cracked in minutes to hours with efficient attacks

### 3. Hard Shadow File (bcrypt)

- Uses `$2a$10$` prefix with cost factor of 10
- Implements key stretching with 2^10 iterations
- Specifically designed to be slow (thousands of times slower than SHA-256)
- Highly resistant to hardware acceleration (GPU attacks)
- Can take days to years to crack even with sophisticated attacks

## Security Demonstration

When running our password cracker against these files, you'll observe:

1. Dictionary attacks succeed quickly against easy_shadow.txt
2. Dictionary and brute force take significantly longer against medium_shadow.txt
3. Rainbow tables fail completely against properly salted passwords
4. All attack methods struggle or time out against hard_shadow.txt

## Defensive Techniques Demonstrated

1. **Salting**: All shadow files use salting (random values in the hash) to prevent pre-computation attacks
2. **Algorithm Strength**: Moving from MD5 to SHA-256 increases security
3. **Key Stretching**: bcrypt's adaptable work factor creates significant computational overhead

This project serves as both an offensive security testing tool and an educational demonstration of password security principles.

## Why Common Passwords Matter

The `data/common_passwords.txt` file demonstrates why dictionary attacks are so effective:

- Studies show 10-20 most common passwords cover ~10% of all user accounts
- 80% of compromises come from the top 5,000 passwords
- Time to crack a password using a dictionary: seconds to minutes
- Time to crack the same password with brute force: potentially years

Our demonstration shows how a simple dictionary of just 20 common passwords successfully cracks multiple accounts in the easy shadow file within seconds, highlighting why password education is as important as technical measures.
