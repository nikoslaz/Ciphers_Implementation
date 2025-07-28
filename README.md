Nikolaos Lazaridis - csd4922

## Part A: Ciphers Implementation

This section details the implementation of various classical ciphers.

### One-time pad

> Encrypts and decrypts data using the XOR operation with a randomly generated key of the same length as the message. It's theoretically unbreakable if the key is truly random, used only once, and kept secret.

*   Reads the input data byte by byte.
*   Performs the XOR operation for both encryption and decryption using the generated key.
*   Generates a cryptographically secure random key using `os.urandom`.
*   Includes a helper function to print raw data in hexadecimal format for verification purposes.

### Affine cipher

> A monoalphabetic substitution cipher where each letter in the alphabet is mapped to its numeric equivalent, encrypted using a simple linear function `(ax + b) mod 26`, and converted back to a letter. Decryption uses the inverse function.

*   Reads the input byte by byte.
*   Applies the encryption formula `(ax + b) mod 26` to alphabetic characters (case-insensitive).
*   Applies the decryption formula `a^-1 * (x - b) mod 26` using the modular multiplicative inverse of `a` for alphabetic characters (case-insensitive).
*   Preserves the original case and the position of non-alphabetic characters.

### Substitution Decryptor

This tool attempts to decrypt a substitution cipher given the ciphertext and the corresponding plaintext.

**Ciphertext:**

```
Vrq wdgvr mati, ichhqmm, cz Lqbqem' mct, Gyrabbqm, vrgv hqmvdeyvanq wdgvr wrayr pdceirv ycetvbqmm wcqm elct vrq Gyrgqgtm, gth mqtv zcdvr vc Rghqm kgto ngbagtv mcebm cz rqdcqm, gth kghq vrqk vrqkmqbnqm mlcab zcd hcim gth qnqdo padh;
```

**Plaintext:**

```
The wrath sing, goddess, of Peleus' son, Achilles, that destructive wrath which brought countless woes upon the Achaeans, and sent forth to Hades many valiant souls of heroes, and made them themselves spoil for dogs and every bird;
```

**Derived Letter Mapping (Cipher -> Plain):**

```
a -> i       h -> d       o -> y      v -> t
b -> l       i -> g       p -> l      w -> w
c -> o       j -> null    q -> e      x -> null
d -> r       k -> m       r -> h      y -> c
e -> u       l -> p       s -> null   z -> f
f -> null    m -> s       t -> n
g -> a       n -> v       u -> null
```
*(Note: 'null' indicates the cipher letter was not present in the provided ciphertext sample)*

### Scytale cipher

> A transposition cipher that simulates writing a message on a strip of parchment wrapped around a cylinder (scytale) of a specific diameter (represented by the number of 'columns' or 'rods'). The ciphertext is formed by reading the letters down the columns. Decryption involves simulating the same wrapping and reading across the rows.

*   **Encryption:**
    *   Calculates the required grid dimensions (rows x columns) based on the text length and the specified number of columns (key).
    *   Fills the grid row by row with the alphabetic characters from the input text.
    *   Reads the grid column by column to produce the ciphertext.
*   **Decryption:**
    *   Calculates the grid dimensions similarly.
    *   Fills the grid column by column with the alphabetic characters from the ciphertext.
    *   Reads the grid row by row to recover the plaintext sequence.
*   **Restoration:**
    *   A helper function restores the original case and positions of non-alphabetic characters from the initial text into the decrypted alphabetic sequence.