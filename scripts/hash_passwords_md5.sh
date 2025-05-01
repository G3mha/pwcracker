#!/bin/bash

# Define absolute paths (recommended for debugging)
input_file="./data/test_pws_salted.txt"
output_file="./data/test_md5_hashed.txt"

# Clear the output file
> "$output_file"

# Read each password from the input file and hash it
while IFS= read -r password || [ -n "$password" ]; do
  echo "Hashing: $password"
  if [ -n "$password" ]; then
    hash=$(md5 -s "$password" | cut -d ' ' -f4)
    echo "$hash" >> "$output_file"
  fi
done < "$input_file"

echo "MD5 hashes written to $output_file"
