# Hashinator

🔥 Identify hashes blazingly fast

## Table of Contents
- [About](#about)
- [Installation](#installation)
- [Usage](#usage)

## About
 * 🚀 **Blaingly Fast** - Built with the rust programming language allowing blazingly fast hash identificaiton.
 * 📚 **Informative Summary** - Popular hashes come with a description of what it is used for and where it can be found allowing you to make a more informed decision.
 * 💯 **Hash Ranknig** - Hashes are ranked by popularity allowing for the most likley hashes to appear straight away.
 * ⚙️ **Built With Rust** - Built with the rust programing language, that alone should be enough.

## Installation 
```
cargo install hashinator
```
if you have run the above command and it is still not working you may need to add .cargo/bin to your path this can be achived by adding this line to your .bashrc or equivilant
```
export PATH=$HOME/.cargo/bin:$PATH
```
## Usage
```
hashinator -t 1bc43a00ffd1a6ac361dae94f46cdc44
hashinator -f file_containing_a_hash_on_each_line.txt
hashinator -t 1bc43a00ffd1a6ac361dae94f46cdc44 -v 
```
