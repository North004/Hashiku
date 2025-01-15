# Hashinator
A tool to identify the hashing algorithm used to create the provided hash 
along with incliuding usefull information such as the john the ripper and hashcat identification number to aid in the cracking of the hash along with a brief descripton of the hashes uses and likley place you would find it.

## Installation
```bash
cargo install hashinator
```

## Usage
1. identify the below hash
```bash
hashinator -t 1ecdeba4b67bf053507826c355828a30 
```
2. identify all hashes in the file
```bash
hashinator -f file
```
3. identify the hash with verbose output
```bash
hashinator -v -t 1ecdeba4b67bf053507826c355828a30  
```
