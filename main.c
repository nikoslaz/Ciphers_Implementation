#include "cs457_crypto.h"

void OTP_examples() {
    // --- Test 1: ---
    printf("--- Test Case 1: Original ---\n");
    const char* plaintext1 = "ThisIsACat";
    size_t size1 = strlen(plaintext1); 
    printf("Plaintext: \"%s\"\n", plaintext1);
    printf("Generating key of size %zu...\n", size1);
    char* key_str1 = generate_key(size1);
    if (key_str1 == NULL) {
        fprintf(stderr, "Failed to generate key for Test Case 1.\n");
    } else {
        call_OTP(plaintext1, key_str1, size1); 
        free(key_str1);
    }
    printf("----------------------------\n\n");

    // --- Test Case 2: Different Plaintext ---
    printf("--- Test Case 2: ---\n");
    const char* plaintext2 = "HELLO WORLD";
    size_t size2 = strlen(plaintext2);
    printf("Plaintext: \"%s\"\n", plaintext2);
    printf("Generating key of size %zu...\n", size2);
    char* key_str2 = generate_key(size2);
    if (key_str2 == NULL) {
        fprintf(stderr, "Failed to generate key for Test Case 2.\n");
    } else {
        call_OTP(plaintext2, key_str2, size2);
        free(key_str2);
    }
    printf("-------------------------------------\n\n");

    // --- Test Case 3: ---
    printf("--- Test Case 3: Mixed Case and Symbols ---\n");
    const char* plaintext3 = "NikoS2525!@#";
    size_t size3 = strlen(plaintext3);
    printf("Plaintext: \"%s\"\n", plaintext3);
    printf("Generating key of size %zu...\n", size3);
    char* key_str3 = generate_key(size3);
    if (key_str3 == NULL) {
        fprintf(stderr, "Failed to generate key for Test Case 3.\n");
    } else {
        call_OTP(plaintext3, key_str3, size3);
        free(key_str3);
    }
    printf("-------------------------------------------\n\n");

    // --- Test Case 4:  ---
    printf("--- Test Case 4: Empty Plaintext ---\n");
    const char* plaintext4 = "";
    size_t size4 = strlen(plaintext4);
    printf("Plaintext: \"%s\"\n", plaintext4);
    printf("Generating key of size %zu...\n", size4);

    char* key_str4 = generate_key(size4); 
    if (key_str4 == NULL && size4 > 0) {
         fprintf(stderr, "Failed to generate key for Test Case 4.\n");
    } else {
        call_OTP(plaintext4, key_str4, size4); 
        if (key_str4 != NULL) { 
             free(key_str4);
        }
    }
    printf("----------------------------------\n\n");

    // --- Test Case 5: ---
    printf("--- Test Case 5: Longer Plaintext ---\n");
    const char* plaintext5 = "Test a reallyyyyyyyyyyyyyy longgggggggggggggggg messageeeeeeeeeeeeee!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!.";
    size_t size5 = strlen(plaintext5);
    printf("Plaintext: \"%s\"\n", plaintext5);
    printf("Generating key of size %zu...\n", size5);
    char* key_str5 = generate_key(size5);
    if (key_str5 == NULL) {
        fprintf(stderr, "Failed to generate key for Test Case 5.\n");
    } else {
        call_OTP(plaintext5, key_str5, size5);
        free(key_str5);
    }
    printf("-----------------------------------\n\n");
}

void affine_examples() {
    // --- Test Case 1:  ---
    const char* message1 = "ThisIsACat";
    printf("--- Affine Cipher Example 1 ---\n");
    printf("Plaintext: \"%s\"\n", message1);
    call_affine(message1);
    printf("-------------------------------\n\n");

    // --- Test Case 2: ---
    const char* message2 = "HELLO WORLD"; 
    printf("--- Affine Cipher Example 2 ---\n");
    printf("Plaintext: \"%s\"\n", message2);
    call_affine(message2);
    printf("-------------------------------\n\n");

    // --- Test Case 3: ---
    const char* message3 = "Number2002"; 
    printf("--- Affine Cipher Example 3 ---\n");
    printf("Plaintext: \"%s\"\n", message3);
    call_affine(message3);
    printf("-------------------------------\n\n");

    // --- Test Case 4: ---
    const char* message4 = ""; 
    printf("--- Affine Cipher Example 4 ---\n");
    printf("Plaintext: \"%s\"\n", message4);
    call_affine(message4);
    printf("-------------------------------\n\n");

    // --- Test Case 5: ---
    const char* message5 = "Nikos Lazaridis 22";
    printf("--- Affine Cipher Example 5 ---\n");
    printf("Plaintext: \"%s\"\n", message5);
    call_affine(message5);
    printf("-------------------------------\n\n");
}

void sub_example() {
    const char cipher_text[] = "Vrq wdgvr mati, ichhqmm, cz Lqbqem' mct, Gyrabbqm, vrgv "
                               "hqmvdeyvanq wdgvr wrayr pdceirv ycetvbqmm wcqm elct vrq Gyrgqgtm, gth mqtv "
                               "zcdvr vc Rghqm kgto ngbagtv mcebm cz rqdcqm, gth kghq vrqk vrqkmqbnqm mlcab "
                               "zcd hcim gth qnqdo padh;";

    sub_decryptor(cipher_text);
}

void scytale_examples() {
    // --- Test Case 1: ---
    const char* message1 = "I am hurt very badly help";
    int diameter1 = 5;

    printf("--- Scytale Test Case 1 ---\n");
    printf("Original:          \"%s\"\n", message1);
    printf("Diameter:          %d\n", diameter1);

    char* encrypted1 = scytale_encr(message1, diameter1);
    if (encrypted1) {
        printf("Encrypted (Letters): \"%s\"\n", encrypted1);

        char* decrypted_letters1 = scytale_decr(encrypted1, diameter1);
        if (decrypted_letters1) {
            printf("Decrypted (Letters): \"%s\"\n", decrypted_letters1);

            char* final_restored_text1 = restore_original(decrypted_letters1, message1);
            if (final_restored_text1) {
                printf("Restored Format:   \"%s\"\n", final_restored_text1);
                free(final_restored_text1);
            } else {
                fprintf(stderr, "Failed to restore format for Test Case 1.\n");
            }

            free(decrypted_letters1);
        } else {
            fprintf(stderr, "Decryption failed for Test Case 1.\n");
        }
        free(encrypted1);
    } else {
        fprintf(stderr, "Encryption failed for Test Case 1.\n");
    }
    printf("--------------------------\n\n");

    // --- Test Case 2: ---
    const char* message2 = "Meet me at the usual place";
    int diameter2 = 7;

    printf("--- Scytale Test Case 2 ---\n");
    printf("Original:          \"%s\"\n", message2);
    printf("Diameter:          %d\n", diameter2);

    char* encrypted2 = scytale_encr(message2, diameter2);
    if (encrypted2) {
        printf("Encrypted (Letters): \"%s\"\n", encrypted2);
        char* decrypted_letters2 = scytale_decr(encrypted2, diameter2);
        if (decrypted_letters2) {
            printf("Decrypted (Letters): \"%s\"\n", decrypted_letters2);
            char* final_restored_text2 = restore_original(decrypted_letters2, message2);
            if (final_restored_text2) {
                printf("Restored Format:   \"%s\"\n", final_restored_text2);
                free(final_restored_text2);
            } else {
                fprintf(stderr, "Failed to restore format for Test Case 2.\n");
            }
            free(decrypted_letters2);
        } else {
            fprintf(stderr, "Decryption failed for Test Case 2.\n");
        }
        free(encrypted2);
    } else {
        fprintf(stderr, "Encryption failed for Test Case 2.\n");
    }
    printf("--------------------------\n\n");

    // --- Test Case 3: ---
    const char* message3 = "Attack at dawn! Code: 123";
    int diameter3 = 4;

    printf("--- Scytale Test Case 3 ---\n");
    printf("Original:          \"%s\"\n", message3);
    printf("Diameter:          %d\n", diameter3);

    char* encrypted3 = scytale_encr(message3, diameter3);
    if (encrypted3) {
        printf("Encrypted (Letters): \"%s\"\n", encrypted3);
        char* decrypted_letters3 = scytale_decr(encrypted3, diameter3);
        if (decrypted_letters3) {
            printf("Decrypted (Letters): \"%s\"\n", decrypted_letters3);
            char* final_restored_text3 = restore_original(decrypted_letters3, message3);
            if (final_restored_text3) {
                printf("Restored Format:   \"%s\"\n", final_restored_text3);
                free(final_restored_text3);
            } else {
                fprintf(stderr, "Failed to restore format for Test Case 3.\n");
            }
            free(decrypted_letters3);
        } else {
            fprintf(stderr, "Decryption failed for Test Case 3.\n");
        }
        free(encrypted3);
    } else {
        fprintf(stderr, "Encryption failed for Test Case 3.\n");
    }
    printf("--------------------------\n\n");

    // --- Test Case 4: ---
    const char* message4 = "";
    int diameter4 = 5;

    printf("--- Scytale Test Case 4 ---\n");
    printf("Original:          \"%s\"\n", message4);
    printf("Diameter:          %d\n", diameter4);

    char* encrypted4 = scytale_encr(message4, diameter4);
    if (encrypted4) {
        printf("Encrypted (Letters): \"%s\"\n", encrypted4); 
        char* decrypted_letters4 = scytale_decr(encrypted4, diameter4);
        if (decrypted_letters4) {
            printf("Decrypted (Letters): \"%s\"\n", decrypted_letters4); 
            char* final_restored_text4 = restore_original(decrypted_letters4, message4);
             if (final_restored_text4) {
                printf("Restored Format:   \"%s\"\n", final_restored_text4); 
                free(final_restored_text4);
            } else {
                 fprintf(stderr, "Failed to restore format for Test Case 4.\n");
            }
            free(decrypted_letters4);
        } else {
            fprintf(stderr, "Decryption failed for Test Case 4.\n");
        }
        free(encrypted4);
    } else {
        fprintf(stderr, "Encryption failed for Test Case 4.\n");
    }
    printf("--------------------------\n\n");

    // --- Test Case 5: ---
    const char* message5 = "A really longgggggggggggggggggggggggggggg messageeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee helooooooooooooooooooooooooooooooooooooooooooooo.";
    int diameter5 = 10;

    printf("--- Scytale Test Case 5 ---\n");
    printf("Original:          \"%s\"\n", message5);
    printf("Diameter:          %d\n", diameter5);

    char* encrypted5 = scytale_encr(message5, diameter5);
    if (encrypted5) {
        printf("Encrypted (Letters): \"%s\"\n", encrypted5);
        char* decrypted_letters5 = scytale_decr(encrypted5, diameter5);
        if (decrypted_letters5) {
            printf("Decrypted (Letters): \"%s\"\n", decrypted_letters5);
            char* final_restored_text5 = restore_original(decrypted_letters5, message5);
            if (final_restored_text5) {
                printf("Restored Format:   \"%s\"\n", final_restored_text5);
                free(final_restored_text5);
            } else {
                fprintf(stderr, "Failed to restore format for Test Case 5.\n");
            }
            free(decrypted_letters5);
        } else {
            fprintf(stderr, "Decryption failed for Test Case 5.\n");
        }
        free(encrypted5);
    } else {
        fprintf(stderr, "Encryption failed for Test Case 5.\n");
    }
    printf("--------------------------\n\n");
}

int main() {
    OTP_examples(); // Call OTP examples
    affine_examples(); // Call Affine examples
    // sub_example(); // Call Substitution example
    scytale_examples(); // Call Scytale examples
    return 0; 
}