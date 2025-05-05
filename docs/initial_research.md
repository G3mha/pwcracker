# Offensive Techniques

## Brute Forcing

- time consuming
- literally just guess random things (like a discrete problem)
- longer, more complex passwords are really effective for foiling this

## Dictionary Attacks

- Based upon a collection of common passwords
  - generally popular passwords
  - previouslly captured attacks

## Rainbow Tables

- precomputed tables to reserve crytographic hash functions
  - contains password hash value for each plaintext character
  - can use that to backwards engineer passwords from password hashes
- more efficient than other (previous) methods
- hash chains
  - sequence of hash and reduction functions
- limitations
  - size dependent on several variables, like possible passwords, character options, and password lengths
  - larger complexities leads to impractical table sizes
- different from precomputed hash datatables
  - those contain hashes for every possible password
  - rainbow tables are smaller
- salting really makes rainbow table attacks a lot harder
- it is possible to find rainbow tables online for every common hashing standard

- Sources
  - https://www.youtube.com/watch?v=T0QfilwNFE4
  - https://www.beyondidentity.com/glossary/rainbow-table-attack
  - https://www.techtarget.com/whatis/definition/rainbow-table
  - Good article, walks through an example: https://www.ionos.com/digitalguide/server/security/rainbow-tables/
  - A simple implementation in C: https://github.com/jhayes14/RainbowTable
  - Basic intro video: https://www.youtube.com/watch?v=SOV0AeHuHaQ

### Isha's questions

- if most/all of these methods involve stealing a hashed password or a hashed table to begin with, isn't that fairly significant overhead? How easy is it to do that? --> yes. These exist through datal eaks
- When you have a rainbow table and you're talking about having all the hashes available, is that because there are a couple of standard hashing functions and some standard passwords? --> yes, you must know the hashing function used or have a separate table for each type of guess
  - wouldn't this not work if people didn't use a basic password and/or the encryption didn't use a basic/known hashing function?
- How does reducing work in a hash chain? --> something something can compress the data so your table needs less storage, because you don't have to store every single guess. If you find a match, you can reconstruct the chain backwards to get the original plaintext.
- How computationally intensive is it to create the rainbow table? --> not computationally expensive at the time of cracking becuase you've already produced the table.

# Defensive Techniques

## Hashing

- "taking a large amount of data and turning it into a small amount of data to be able to verify it"
  - should not be used for actually keeping things secure
- one way encryption
  - not able to be decrypted
  - mainly meant for comparison purposes
- used to make sure that something is what it says it is
  - a "signature" of sorts to make sure that some data hasn't been changed
- other applications
  - message or file integrity (nothing has been tampered with)
  - password validation
  - blockchain and transaction validation
- Requirements
  - reasonably fast
    - can compress an entire file
    - but shouldn't be too fast becase that's easier to break
  - one changed bit anywhere should make the whole hash completly different (avalanche effect)
  - reduce hash collisions
    - this is when two different keys generate the same value
- Collision resolution methods
  - Open addressing (closed hashing)
    - if colliding, go through table and find an empty slot to store the colliding key value
  - Separate chaining (open hashing)
    - each slot in has table acts like linked list and can hold multiple key values
- Existing and old methods
  - md5 used to be the standard, but now it's really easy to break (even just using google)
  - sha1 used but now computers are getting faster, so they have sha2 and sha3
- Hash functions map key to an index which corresponds to a value

  - indices and values are stored in a hash table or hash map

- Sources
  - https://builtin.com/articles/what-is-hashing

## Salting

- adding little bits of randomness to hashing
- quite effective against rainbow table attacks

## Shadow Files

## General Encryption
