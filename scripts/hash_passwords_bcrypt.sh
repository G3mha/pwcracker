#!/bin/bash

# Define absolute paths (recommended for debugging)
input_file="./data/test_pws_salted.txt"
output_file="./data/test_hashed_bcrypt.txt"

# Clear the output file
> "$output_file"

# Read each password from the input file and hash it
while IFS= read -r password || [ -n "$password" ]; do
  echo "Hashing: $password"
  if [ -n "$password" ]; then
      hash=$(htpasswd -bnBC 10 "" "$password" | tr -d ':\n' | sed 's/^ //')
    echo "$hash" >> "$output_file"
  fi
done < "$input_file"

echo "bcrypt hashes written to $output_file"
