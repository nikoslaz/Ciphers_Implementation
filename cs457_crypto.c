#include "cs457_crypto.h"

/* ------------------------- ONE TIME PAD ------------------------- */

char* one_time_pad_encr(const char* plain_text, size_t size, const char* key){
    if (plain_text == NULL) return NULL;
    // + 1 for '\0'
    char* cipherText = (char*)malloc(size + 1);
    if (cipherText == NULL) {
        perror("Memory allocation failed in one_time_pad_encr");
        return NULL;
    }

    // For every byte in the plaintext, XOR with the key byte
    for (size_t i = 0; i < size; i++) {
        cipherText[i] = ((unsigned char)plain_text[i]) ^ ((unsigned char)key[i]);
    }

    cipherText[size] = '\0';

    return cipherText;
}

char* one_time_pad_decr(const char* cipher_text, size_t size, const char* key){
    if (cipher_text == NULL) return NULL;
    // + 1 for the null terminator '\0'.
    char* plainText = (char*)malloc(size + 1);
    if (plainText == NULL) {
        perror("Memory allocation failed in one_time_pad_decr");
        return NULL;
    }

    // For every byte in the ciphertext, XOR with the key byte
    for (size_t i = 0; i < size; i++) {
        plainText[i] = ((unsigned char)cipher_text[i]) ^ ((unsigned char)key[i]);
    }

    plainText[size] = '\0';

    return plainText;
}

// Helper function to print raw data as hex
void print_hex(const char* label, const unsigned char* data, size_t size) {
    printf("%s (hex, %zu bytes): ", label, size);
    if (data == NULL) {
        printf("NULL\n");
        return;
    }
    for (size_t i = 0; i < size; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void call_OTP(const char* plain_text, const char* key_str, size_t data_size) {

    printf("--- Encryption ---\n");
    char* encrypted_text = one_time_pad_encr(plain_text, data_size, key_str);

    if (encrypted_text != NULL) {
        printf("Plaintext:  %s\n", plain_text);
        print_hex("Key       ", (const unsigned char*)key_str, data_size);
        print_hex("Ciphertext", (const unsigned char*)encrypted_text, data_size);

        printf("\n--- Decryption ---\n");
        char* decrypted_text = one_time_pad_decr(encrypted_text, data_size, key_str);

        if (decrypted_text != NULL) {
            print_hex("Ciphertext", (const unsigned char*)encrypted_text, data_size);
            print_hex("Key       ", (const unsigned char*)key_str, data_size);
            printf("Decrypted: %s\n", decrypted_text);

            if (memcmp(plain_text, decrypted_text, data_size) == 0) {
                printf("Verification: Decryption successful! Output matches original plaintext bytes.\n");
            } else {
                printf("Verification: WARNING - Decryption output does NOT match original plaintext bytes.\n");
            }

            free(decrypted_text);
        } else {
            fprintf(stderr, "Decryption failed.\n");
        }

        free(encrypted_text);

    } else {
        fprintf(stderr, "Encryption failed.\n");
    }
}

char* generate_key(size_t length) {
    if (length == 0) {
        char* empty_key = (char*)malloc(1);
        if (empty_key != NULL) {
            empty_key[0] = '\0';
        }
        return empty_key;
    }

    char* key = NULL;
    int urandom_fd = -1;

    key = (char*)malloc(length + 1);
    if (key == NULL) {
        perror("Failed to allocate memory for key");
        return NULL;
    }

    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        perror("Failed to open /dev/urandom");
        free(key);
        return NULL;
    }

    // Read random bytes directly into the key buffer
    read(urandom_fd, key, length);

    close(urandom_fd);
    urandom_fd = -1;

    key[length] = '\0';

    return key;
}

/* ------------------------- AFFINE CIPHER ------------------------- */
const int a = 3;
const int b = 8;
const int a_inv = 9;

char* affine_encr(const char* plain_text) {
    if (plain_text == NULL) return NULL;
    size_t size = strlen(plain_text);
    //+ 1 for the null terminator
    char* cipherText = (char*)malloc(size + 1);
    if (cipherText == NULL) {
        perror("Memory allocation failed in affine_encr");
        return NULL;
    }

    for (size_t i = 0; i < size; i++) {
        char current_char = plain_text[i];
        char base_char = 0; // To store 'A' or 'a'

        if (isalpha(current_char)) {
            // Determine base ('A' or 'a') based on case
            if (isupper(current_char)) {
                base_char = 'A';
            } else { // islower(current_char)
                base_char = 'a';
            }

            // Calculate numerical value (0-25) relative to the base
            int char_val = current_char - base_char;
            // Apply affine encryption formula
            int encrypted_val = (a * char_val + b) % 26;
            // Convert back to letter
            cipherText[i] = (char)(encrypted_val + base_char);

        } else {
            // non-alphabetic characters
            cipherText[i] = current_char;
        }
    }

    cipherText[size] = '\0'; 

    return cipherText;
}

char* affine_decr(const char* cipher_text) {
    if (cipher_text == NULL) return NULL; 
    size_t size = strlen(cipher_text);
    // + 1 for the null terminator
    char* plainText = (char*)malloc(size + 1);
    if (plainText == NULL) {
        perror("Memory allocation failed in affine_decr");
        return NULL;
    }

    for (size_t i = 0; i < size; i++) {
        char current_char = cipher_text[i];
        char base_char = 0; // To store 'A' or 'a'

        if (isalpha(current_char)) {
             // Determine base ('A' or 'a') based on case
            if (isupper(current_char)) {
                base_char = 'A';
            } else { // islower(current_char)
                base_char = 'a';
            }

            // Calculate numerical value (0-25) relative to the base
            int char_val = current_char - base_char;
            // Apply affine decryption formula
            int shifted_val = char_val - b;
            int decrypted_val = a_inv * shifted_val;
            // (val % 26 + 26) % 26 handles negative results correctly
            int decrypted_mod = (decrypted_val % 26 + 26) % 26;
            // Convert to letter
            plainText[i] = (char)(decrypted_mod + base_char);

        } else {
            // non-alphabetic 
            plainText[i] = current_char;
        }
    }

    plainText[size] = '\0'; 

    return plainText;
}

void call_affine(const char* message) {
    printf("Original:   %s\n", message);

    char* encrypted = affine_encr(message);
    if (encrypted) {
        printf("Encrypted:  %s\n", encrypted);

        char* decrypted = affine_decr(encrypted);
        if (decrypted) {
            printf("Decrypted:  %s\n", decrypted);
            free(decrypted);
        } else {
            fprintf(stderr, "Decryption failed.\n");
        }
        free(encrypted);
    } else {
        fprintf(stderr, "Encryption failed.\n");
    }
}

/* ------------------------- SUBSTITUTION DECRYPTOR ------------------------- */

// Define sizes
#define ALPHABET_SIZE 26
#define INITIAL_DICT_CAPACITY 10000
#define MAX_WORD_LEN 1000

// Map alphabet
char map_alphabet[ALPHABET_SIZE];

// Store words
char **dictionary       = NULL;
int dictionary_size     = 0;
int dictionary_capacity = 0;

// free dictionary memory
static void cleanup_dictionary() {
    if (dictionary) {
        for (int i = 0; i < dictionary_size; i++) {
            free(dictionary[i]);
        }
        free(dictionary); 
        dictionary = NULL;
        dictionary_size = 0;
        dictionary_capacity = 0;
    }
}

int load_dictionary() {
    // Load dictionary
    FILE *file = fopen("words.txt", "r");
    if (!file) {
        perror("Error opening dictionary file 'words.txt'");
        return 0;
    }

    dictionary_capacity = INITIAL_DICT_CAPACITY;
    dictionary_size = 0;
    dictionary = (char**)malloc(dictionary_capacity * sizeof(char*));
    if (!dictionary) {
        perror("Error allocating memory for dictionary");
        fclose(file);
        return 0;
    }

    char line[MAX_WORD_LEN]; 
    while (fgets(line, sizeof(line), file)) {
        // Remove newline/carriage return
        line[strcspn(line, "\r\n")] = 0;

        // Resize if needed
        if (dictionary_size >= dictionary_capacity) {
            dictionary_capacity *= 2;
            char **temp = (char **)realloc(dictionary, dictionary_capacity * sizeof(char *));
            if (!temp) {
                perror("Error reallocating memory for dictionary");
                fclose(file);
                return 0;
            }
            dictionary = temp;
        }

        // Store the word and convert to lowercase
        dictionary[dictionary_size] = strdup(line);
        if (!dictionary[dictionary_size]) {
            perror("Error duplicating dictionary word (strdup)");
            fclose(file);
            cleanup_dictionary();
            return 0;
        }

        // Convert to lowercase 
        for(char *p = dictionary[dictionary_size]; *p; ++p) *p = tolower(*p);
        dictionary_size++;
    }

    fclose(file);
    printf("Dictionary loaded (%d words).\n", dictionary_size);
    return 1;
}

char* apply_mapping(const char* cipher_text) {
    size_t size = strlen(cipher_text);
    char *result = (char *)malloc(size + 1);
    if (!result) {
        perror("Error allocating memory in apply_mapping");
        return NULL;
    }

    for (size_t i = 0; i < size; i++) {
        if (isalpha(cipher_text[i])) {
            int index = toupper(cipher_text[i]) - 'A';
            // Use '*' if unknown
            result[i] = map_alphabet[index];
        } else {
            // Copy non-letters directly
            result[i] = cipher_text[i]; 
        }
    }
    result[size] = '\0';

    return result;
}

void update_mapping(char cipher_char, char plain_char) {
    if (!isalpha(cipher_char) || !isalpha(plain_char)) {
        printf("Error: Both characters must be letters for mapping.\n");
        return;
    }

    // Store plaintext mapping as uppercase
    cipher_char = toupper(cipher_char);
    // Store plaintext mapping as lowercase
    plain_char = tolower(plain_char); 

    int index = cipher_char - 'A';

    // Check if plaintext char is already mapped from another cipher char
    for(int i = 0; i < ALPHABET_SIZE; ++i) {
        if (map_alphabet[i] == plain_char && i != index) {
            printf("Warning: Plaintext '%c' is already mapped from ciphertext '%c'. Overwriting mapping for '%c'.\n",
                plain_char, (char)('A'+i), cipher_char);
        }
    }

    // Check if ciphertext char is already mapped
    if (map_alphabet[index] != '*' && map_alphabet[index] != plain_char) {
        printf("Warning: Ciphertext '%c' was already mapped to '%c'. Changing to '%c'.\n",
            cipher_char, map_alphabet[index], plain_char);
    } else if (map_alphabet[index] == plain_char) {
            printf("Ciphertext '%c' is already mapped to '%c'.\n", cipher_char, plain_char);
    } else {
            printf("Mapping: %c -> %c\n", cipher_char, plain_char);
    }

    map_alphabet[index] = plain_char;
}

int is_consistent(const char *dict_word, const char *cipher_segment) {
    size_t size = strlen(dict_word);
    if (strlen(cipher_segment) != size) return 0; 

    for (size_t i = 0; i < size; i++) {
        // If ciphertext has non-letter where dictionary expects one, it's inconsistent
        if (!isalpha(cipher_segment[i])) {
            if (isalpha(dict_word[i])) return 0;
            continue;  
        }

        int index = toupper(cipher_segment[i]) - 'A';
        char mapped_char = map_alphabet[index];

        // Check if cipher char is mapped, but not to the dict word's char
        if (mapped_char != '*' && mapped_char != dict_word[i]) {
            return 0;
        }
    }

    return 1;
} 

int pattern_matches_word(const char *pattern, const char *word) {
    size_t len = strlen(pattern);
    if (strlen(word) != len) return 0;

    for (size_t i = 0; i < len; i++) {
        if (pattern[i] != '*' && tolower(pattern[i]) != word[i]) {
            return 0;
        }
    }
    return 1;
}

void find_matches(const char *pattern, const char* cipher_text) {
    size_t patter_size = strlen(pattern);
    int found_count = 0;
    char **matched_words = malloc(dictionary_size * sizeof(char*));
    if (!matched_words) {
        perror("Failed to allocate memory for match results");
        return;   
    }
    int matches_idx = 0;

    for (int i = 0; i < dictionary_size; i++) {
        // Per word
        const char* word = dictionary[i];
        // needs to be the same
        if (strlen(word) != patter_size) continue; 
        // Check if the dictionary word match the user's pattern
        if (!pattern_matches_word(pattern, word)) continue;

        // Check if word is consistent with any ciphertext segment
        int consistent_somewhere = 0;
        const char *text_ptr = cipher_text;
        while ((text_ptr = strstr(text_ptr, ""))) {
            // Check if pattern fits within the text
            if (text_ptr - cipher_text + patter_size > strlen(cipher_text)) break;

            // Create a temporary substring for the cipher segment
            char cipher_segment[MAX_WORD_LEN + 1];
            if (patter_size > MAX_WORD_LEN) continue;
            strncpy(cipher_segment, text_ptr, patter_size);
            cipher_segment[patter_size] = '\0';
            // Check consistency
            if (is_consistent(word, cipher_segment)) {
                consistent_somewhere = 1;
                break;
            }

            text_ptr++; 
        }

        if (consistent_somewhere) {
            int already_found = 0;
            // Check if we have it on matched_words
            for (int j = 0; j < matches_idx; j++) {
                if (strcmp(matched_words[j], word) == 0) {
                    already_found = 1;
                    break;
                }
            }
            
            // Was not found store it
            if (!already_found) {
                if (found_count == 0) printf("Potential matches: ");
                else printf(", ");
                printf("%s", word);
                matched_words[matches_idx++] = (char*)word; 
                found_count++;
            }
        }
    }

    if (found_count == 0) {
        printf("No potential matches found.\n");
    } else {
        printf("\n");
    }
    free(matched_words);
}

void sub_decryptor(const char* cipher_text) {
    if (cipher_text == NULL) return; 

    // Store words on dictionary
    if (load_dictionary() == 0) {
        perror("Error loading dictionary\n");
        return;
    }

    // Init to unkown
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        map_alphabet[i] = '*';
    }

    // For input
    char input_buffer[MAX_WORD_LEN];
    // For letter input
    char c_char_in;
    char p_char_in; 
    // For word input
    char pattern_in[MAX_WORD_LEN];
    char *partial_plaintext = NULL;

    while (1) {
        partial_plaintext = apply_mapping(cipher_text);
        if (!partial_plaintext) {
            fprintf(stderr, "Error applying mapping.\n");
            break; 
        }
        printf("\nCiphertext:\n%s\n\n", cipher_text);
        printf("Current Plaintext Guess:\n%s\n", partial_plaintext);
        free(partial_plaintext); 
        partial_plaintext = NULL;

        printf("\n--- Substitution Decryptor Menu ---\n");
        printf("  m c p  - Map ciphertext letter 'c' to plaintext 'p' (e.g., m V t)\n");
        printf("  p pat  - Find potential dictionary words matching pattern 'pat' (use * for unknown, e.g., p t*e)\n");
        printf("  q      - Quit\n");
        printf("Enter command: ");

        if (!fgets(input_buffer, sizeof(input_buffer), stdin)) {
            printf("Error reading input or EOF reached. Exiting.\n");
            break;
        }

        char command_char = input_buffer[0];

        switch (command_char) {
            case 'm':
            case 'M':
                // sscanf needs to skip the command character and potential whitespace
                if (sscanf(input_buffer + 1, " %c %c", &c_char_in, &p_char_in) == 2) {
                    update_mapping(c_char_in, p_char_in);
                } else {
                    printf("Invalid mapping format. Use: m <cipher_char> <plain_char>\n");
                }
                break;

            case 'p':
            case 'P':
                // sscanf needs to skip the command character and potential whitespace
                if (sscanf(input_buffer + 1, " %99s", pattern_in) == 1) {
                     // Ensure pattern only contains letters or '*'
                    int valid_pattern = 1;
                    for(char *ptr = pattern_in; *ptr; ++ptr) {
                        if (!isalpha(*ptr) && *ptr != '*') {
                            valid_pattern = 0;
                            break;
                        }
                    }
                    if (valid_pattern) {
                        find_matches(pattern_in, cipher_text);
                    } else {
                         printf("Invalid pattern: Only letters and '*' allowed.\n");
                    }
                } else {
                    printf("Invalid pattern format. Use: p <pattern>\n");
                }
                break;

            case 'q':
            case 'Q':
                printf("Exiting substitution decryptor.\n");
                cleanup_dictionary();
                return; 

            default:
                if (command_char != '\n') {
                    printf("Invalid command '%c'. Please use 'm', 'p', or 'q'.\n", command_char);
                }
                break;
        }
    }

    if (partial_plaintext) {
        free(partial_plaintext);
    }
    cleanup_dictionary();
   return;
}

/* ------------------------- SCYTALE CIPHER ------------------------- */

char* scytale_encr(const char* plain_text, int rods) {
    if (plain_text == NULL || rods <= 0){
        fprintf(stderr, "Error: Invalid input to scytale_encr.\n");
        return NULL;
    }

    size_t original_size = strlen(plain_text);
    char* after_text = (char*)malloc(original_size + 1);
    if (after_text == NULL) {
        perror("scytale_encr: Failed to allocate memory for after_text");
        return NULL;
    }

    // Filter letters 
    size_t after_size = 0; 
    for (size_t i = 0; i < original_size; i++) {
        if (isalpha((unsigned char)plain_text[i])) {
            after_text[after_size++] = toupper((unsigned char)plain_text[i]);
        }
    }
    after_text[after_size] = '\0';

    // Check size
    if (after_size == 0) {
        free(after_text); 
        return NULL;
    }

    // Calculate grid dimensions
    size_t cols = (size_t)rods;
    size_t rows = (after_size + cols - 1) / cols;
    char* grid = (char*)malloc(rows * cols);
    if (grid == NULL) {
        perror("scytale_encr: Failed to allocate memory for grid");
        free(after_text);
        return NULL;
    }

    // Fill Grid Row-by-Row using after_text
    size_t k = 0; // Index for after_text
    for (size_t r = 0; r < rows; ++r) {
        for (size_t c = 0; c < cols; ++c) {
            // Caclulate index
            size_t grid_idx = r * cols + c;
            if (k < after_size) {
                grid[grid_idx] = after_text[k++];
            } else {
                // Mark
                grid[grid_idx] = '\0';
            }
        }
    }

    char* cipherText = (char*)malloc(after_size + 1);
    if (cipherText == NULL) {
        perror("scytale_encr: Failed to allocate memory for cipherText");
        free(grid);
        free(after_text);
        return NULL;
    }

    // Read Grid Column-by-Column
    size_t cipher_idx = 0;
    for (size_t c = 0; c < cols; ++c) {
        for (size_t r = 0; r < rows; ++r) {
            size_t grid_idx = r * cols + c;
            if (grid[grid_idx] != '\0') { 
                // Check bounds
                if (cipher_idx < after_size) {
                    cipherText[cipher_idx++] = grid[grid_idx];
                }
            }
        }
    }
    cipherText[cipher_idx] = '\0';

    free(grid);
    free(after_text);

    return cipherText;
}


char* scytale_decr(const char* cipher_text, int rods) {
    if (cipher_text == NULL || rods <= 0){
         fprintf(stderr, "Error: Invalid input to scytale_decr.\n");
        return NULL;
    }

    // Ciphertext length = effective length
    size_t after_size = strlen(cipher_text);
    if (after_size == 0) {
        return NULL;
    }

    // Calculate grid dimensions
    size_t cols = (size_t)rods;
    size_t rows = (after_size + cols - 1) / cols;

    // Calculate column 
    size_t num_long_cols = after_size % cols;
    if (num_long_cols == 0 && after_size > 0) {
        num_long_cols = cols;
    }
    size_t long_col_len = rows;
    size_t short_col_len = rows - 1;

    char* grid = (char*)malloc(rows * cols);
    if (grid == NULL) {
        perror("scytale_decr: Failed to allocate memory for grid");
        return NULL;
    }
    memset(grid, '\0', rows * cols);

    char* plain_text = (char*)malloc(after_size + 1);
    if (plain_text == NULL) {
        perror("scytale_decr: Failed to allocate memory for plain_text");
        free(grid);
        return NULL;
    }

    // Fill Grid Column-by-Column from Ciphertext
    size_t k = 0; // Index for cipher_text
    for (size_t c = 0; c < cols; ++c) {
        // How many characters to read for this column
        size_t rows_in_this_col = (c < num_long_cols) ? long_col_len : short_col_len;
        for (size_t r = 0; r < rows_in_this_col; ++r) {
            if (k < after_size) { // Check bounds
                size_t grid_idx = r * cols + c;
                grid[grid_idx] = cipher_text[k++];
            } else {
                fprintf(stderr, "Error index cipher text > after size\n");
                exit(1);
            }
        }
    }


    // Read Grid Row-by-Row to get Plaintext
    size_t plain_idx = 0;
    for (size_t r = 0; r < rows; ++r) {
        for (size_t c = 0; c < cols; ++c) {
            size_t grid_idx = r * cols + c;
            if (grid[grid_idx] != '\0') { // Skip padding
                if (plain_idx < after_size) { // Check bounds
                    plain_text[plain_idx++] = grid[grid_idx];
                } else {
                    fprintf(stderr, "Error index cipher text > after size\n");
                    exit(1);
                }
            }
        }
    }

    plain_text[plain_idx] = '\0';
    free(grid);

    return plain_text;
}

char* restore_original(const char* decrypted_letters, const char* original_text) {
    if (decrypted_letters == NULL || original_text == NULL) {
        fprintf(stderr, "Error: NULL input to restore.\n");
        return NULL;
    }

    size_t template_len  = strlen(original_text);
    size_t decrypted_len = strlen(decrypted_letters);

    char* restored_text = (char*)malloc(template_len + 1);
    if (restored_text == NULL) {
        perror("Failed to allocate memory for restored_text\n");
        return NULL;
    }

    size_t decrypted_idx = 0; // Index for decrypted_letters string
    size_t restored_idx = 0;  // Index for restored_text string

    // Iterate through the original character by character
    for (size_t i = 0; i < template_len; ++i) {
        if (isalpha((unsigned char)original_text[i])) {
            // If is a letter:
            if (decrypted_idx < decrypted_len) {
                // Get the next decrypted letter
                char current_decrypted_char = decrypted_letters[decrypted_idx];

                if (islower((unsigned char)original_text[i])) {
                    restored_text[restored_idx] = tolower((unsigned char)current_decrypted_char);
                } else {
                    restored_text[restored_idx] = toupper((unsigned char)current_decrypted_char);
                }
                decrypted_idx++; 
            }
        } else {
            restored_text[restored_idx] = original_text[i];
        }
        restored_idx++;
    }

    restored_text[restored_idx] = '\0'; 

    return restored_text;
}