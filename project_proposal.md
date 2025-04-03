# Project Proposal

1. **Project Title**: "Password Hash Cracker: Password Security Testing Framework"

2. **GitHub Repository URL**: [Later]

3. **Software to Build**: A framework that enables usage of password cracking techniques (dictionary attacks, rainbow tables, brute force) and defensive countermeasures (salting, key stretching with PBKDF2 and bcrypt).

4. **Minimum Features**:
  - Implementation of at least two attack methods (dictionary and brute force)
  - Basic password hashing with salting
  - One key stretching algorithm implementation (PBKDF2 or bcrypt)
  - Command-line interface for testing password strength
  - Visualization of time taken to crack different password types

5. **C++ Aspects to Learn**:
  - Memory management for handling large dictionaries/hash tables
  - Learn efficient hash implementations in C++
  - Multithreading for parallel cracking attempts
  - Integration with cryptographic libraries

6. **Leadership Aspects**:
  - Attack methods implementation: Enricco Gemha
  - Defensive techniques implementation: Isha Goyal
  - Testing framework, documenting and reporting: Natsuki Sacks

7. **Review Process**:
  - Weekly code reviews using GitHub pull requests
  - Team meetings to discuss the implementation
  - Enricco Gemha and Isha Goyal will review Natsuki Sacks's documentation
  - Enricco Gemha will review his own code, Isha Goyal's code, and Natsuki Sacks's testing

8. **Resources Needed**:
  - OpenSSL or Crypto++ library for cryptographic functions
  - Sample password dictionaries
  - Documentation on hash functions and password security
  - C++ multithreading libraries

9. **Task Tracking**: GitHub Projects with issues and milestones for feature development

10. **Next Tasks**:
  - Natsuki Sacks: Create GitHub repository with project structure and README
  - Isha Goyal: Research and document hash algorithm implementations
  - Enricco Gemha: Set up testing environment and sample datasets
  - Enricco Gemha: Implement basic command-line interface for the framework
