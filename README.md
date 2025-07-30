# Psyfer Ink Packet Builder

- `ink_packet`: Like the cannisters of ink banks put in cash bags. An application builder tool to provide highly tamper-resistant qualities. Some original code exists here, but will need to be adapted to use Psyfer's encryption and hashing algorithms.
    * Steps to the ink packet process:
        1. Select fundamental features of the application to be built into a shared library
        2. Build the shared library, and then the application
        3. The shared library is then encrypted based on the hash of the application binary, and appended to the application binary
        4. At runtime, the application calculates its own hash, decrypts the shared library, and loads it into memory
        5. Placeholders are written into the application binary as constants in a way that they preserve their values after compilation. These values are then patched by finding them in the binary and byte-replacing them with the total hash of the application + shared library binary.
        6. This results in an application binary that, if a single byte is changed, the hash will not match, and the shared library will not be decrypted correctly, causing the application to fail to run.
        