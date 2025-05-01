#!/bin/bash

# Define absolute paths (recommended for debugging)
input_file="./data/test_pws_salted.txt"
output_file="./data/test_hashed_sha256.txt"

# Clear the output file
> "$output_file"

# Read each password from the input file and hash it
while IFS= read -r password || [ -n "$password" ]; do
  if [ -n "$password" ]; then
    hash=$(echo -n "$password" | shasum -a 256 | cut -d ' ' -f1)
    echo "$hash" >> "$output_file"
  fi
done < "$input_file"

echo "SHA-256 hashes written to $output_file"
