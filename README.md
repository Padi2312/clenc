# Clenc

Clenc stands for "**C**ommand **L**ine **Enc**ryption" and is a tool for encrypting and decrypting your files via CLI.


## Usage
> You will be prompted for password after executing the command

**Encrypt:** `./clenc -target ./filename.png -mode encrypt` 

**Decrypt:** `./clenc -target ./filename.png -mode decrypt`


## Options
- `-target`: Specifies the target folder or file to be encrypted
- `-mode`: Sets the operationa mode either `encrypt` or `decrypt`
- `-workers`: Set the number of threads for operations
- `-force`: Force multiple encryptions for same files
