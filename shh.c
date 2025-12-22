#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define CHUNK_SIZE 4096
#define MAGIC "STEG"
#define MAGIC_LEN 4
#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32

void fail() { printf("🖕\n"); exit(1); }

int read_password(const char *prompt, char *password, size_t max_len) {
    struct termios old, new;
    printf("%s", prompt);
    fflush(stdout);
    if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new) != 0) return -1;
    if (fgets(password, max_len, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        return -1;
    }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    printf("\n");
    size_t len = strlen(password);
    if (len > 0 && password[len-1] == '\n') password[len-1] = '\0';
    return 0;
}

long find_iend_mem(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len - 3; i++) {
        if (data[i] == 'I' && data[i+1] == 'E' && data[i+2] == 'N' && data[i+3] == 'D')
            return i;
    }
    return -1;
}

int derive_key(const char *password, const unsigned char *salt, unsigned char *key, unsigned char *iv) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 100000, EVP_sha256(), KEY_LEN + IV_LEN, key) == 1;
}

int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len, total_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    total_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    total_len += len;
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len, total_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    total_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return 0; }
    total_len += len;
    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Base64 encode buffer to file
void b64_encode_mem(const unsigned char *data, size_t len, FILE *output) {
    int line_len = 0;
    for (size_t i = 0; i < len; i += 3) {
        int remaining = len - i;
        unsigned char out[4];
        out[0] = b64_table[data[i] >> 2];
        out[1] = b64_table[((data[i] & 0x03) << 4) | (remaining > 1 ? (data[i+1] >> 4) : 0)];
        out[2] = remaining > 1 ? b64_table[((data[i+1] & 0x0f) << 2) | (remaining > 2 ? (data[i+2] >> 6) : 0)] : '=';
        out[3] = remaining > 2 ? b64_table[data[i+2] & 0x3f] : '=';
        fwrite(out, 1, 4, output);
        line_len += 4;
        if (line_len >= 76) { fprintf(output, "\n"); line_len = 0; }
    }
    if (line_len > 0) fprintf(output, "\n");
}

// Base64 decode file to buffer
unsigned char *b64_decode_file_to_mem(FILE *input, size_t *out_len) {
    fseek(input, 0, SEEK_END);
    size_t file_size = ftell(input);
    rewind(input);
    
    unsigned char *output = malloc(file_size);
    if (!output) return NULL;
    
    size_t out_pos = 0;
    char in[4];
    int i = 0, c;
    
    while ((c = fgetc(input)) != EOF) {
        if (c == '\n' || c == '\r' || c == ' ') continue;
        in[i++] = c;
        if (i == 4) {
            int v[4];
            for (int j = 0; j < 4; j++) v[j] = (in[j] == '=') ? 0 : b64_decode_char(in[j]);
            output[out_pos++] = (v[0] << 2) | (v[1] >> 4);
            if (in[2] != '=') output[out_pos++] = (v[1] << 4) | (v[2] >> 2);
            if (in[3] != '=') output[out_pos++] = (v[2] << 6) | v[3];
            i = 0;
        }
    }
    *out_len = out_pos;
    return output;
}

// Read file to memory
unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    rewind(f);
    unsigned char *data = malloc(*len);
    if (!data) { fclose(f); return NULL; }
    if (fread(data, 1, *len, f) != *len) { free(data); fclose(f); return NULL; }
    fclose(f);
    return data;
}

int hide(const char *png_file, const char *secret_file, const char *output_base) {
    char output_png[512], output_txt[512];
    snprintf(output_png, sizeof(output_png), "%s.png", output_base);
    snprintf(output_txt, sizeof(output_txt), "%s.txt", output_base);
    
    char password[256] = {0}, password2[256] = {0};
    if (read_password("Password: ", password, sizeof(password)) != 0) fail();
    if (strlen(password) > 0) {
        if (read_password("Confirm: ", password2, sizeof(password2)) != 0) fail();
        if (strcmp(password, password2) != 0) fail();
    }
    int use_encryption = strlen(password) > 0;
    
    size_t png_len, secret_len;
    unsigned char *png_data = read_file(png_file, &png_len);
    unsigned char *secret_data = read_file(secret_file, &secret_len);
    if (!png_data || !secret_data) fail();
    
    size_t stego_len;
    unsigned char *stego_data;
    
    if (use_encryption) {
        unsigned char salt[SALT_LEN], key_iv[KEY_LEN + IV_LEN];
        if (RAND_bytes(salt, SALT_LEN) != 1) fail();
        if (!derive_key(password, salt, key_iv, key_iv + KEY_LEN)) fail();
        
        size_t encrypted_size = secret_len + EVP_MAX_BLOCK_LENGTH;
        unsigned char *encrypted = malloc(encrypted_size);
        size_t actual_encrypted_size;
        if (!aes_encrypt(secret_data, secret_len, key_iv, key_iv + KEY_LEN, encrypted, &actual_encrypted_size)) fail();
        
        // PNG + MAGIC + SALT + SIZE + encrypted
        stego_len = png_len + MAGIC_LEN + SALT_LEN + 4 + actual_encrypted_size;
        stego_data = malloc(stego_len);
        if (!stego_data) fail();
        
        size_t pos = 0;
        memcpy(stego_data + pos, png_data, png_len); pos += png_len;
        memcpy(stego_data + pos, MAGIC, MAGIC_LEN); pos += MAGIC_LEN;
        memcpy(stego_data + pos, salt, SALT_LEN); pos += SALT_LEN;
        stego_data[pos++] = (actual_encrypted_size >> 24) & 0xFF;
        stego_data[pos++] = (actual_encrypted_size >> 16) & 0xFF;
        stego_data[pos++] = (actual_encrypted_size >> 8) & 0xFF;
        stego_data[pos++] = actual_encrypted_size & 0xFF;
        memcpy(stego_data + pos, encrypted, actual_encrypted_size);
        
        free(encrypted);
    } else {
        stego_len = png_len + secret_len;
        stego_data = malloc(stego_len);
        if (!stego_data) fail();
        memcpy(stego_data, png_data, png_len);
        memcpy(stego_data + png_len, secret_data, secret_len);
    }
    
    free(png_data);
    free(secret_data);
    
    // Write PNG
    FILE *f_png = fopen(output_png, "wb");
    if (!f_png) fail();
    fwrite(stego_data, 1, stego_len, f_png);
    fclose(f_png);
    
    // Write TXT (base64)
    FILE *f_txt = fopen(output_txt, "w");
    if (!f_txt) fail();
    b64_encode_mem(stego_data, stego_len, f_txt);
    fclose(f_txt);
    
    free(stego_data);
    return 0;
}

int decode(const char *input_file, const char *output_file) {
    size_t data_len;
    unsigned char *data;
    
    FILE *input = fopen(input_file, "rb");
    if (!input) fail();
    
    // Check if PNG
    unsigned char header[4];
    if (fread(header, 1, 4, input) != 4) fail();
    rewind(input);
    
    int is_png = (header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47);
    
    if (is_png) {
        data = read_file(input_file, &data_len);
        fclose(input);
    } else {
        data = b64_decode_file_to_mem(input, &data_len);
        fclose(input);
    }
    if (!data) fail();
    
    long iend_offset = find_iend_mem(data, data_len);
    if (iend_offset < 0) fail();
    
    size_t data_start = iend_offset + 8;
    if (data_start >= data_len) fail();
    
    int is_encrypted = (memcmp(data + data_start, MAGIC, MAGIC_LEN) == 0);
    
    FILE *output = fopen(output_file, "wb");
    if (!output) fail();
    
    if (is_encrypted) {
        char password[256];
        if (read_password("Password: ", password, sizeof(password)) != 0) fail();
        if (strlen(password) == 0) fail();
        
        size_t pos = data_start + MAGIC_LEN;
        unsigned char *salt = data + pos; pos += SALT_LEN;
        
        long enc_size = (data[pos] << 24) | (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
        pos += 4;
        
        unsigned char key_iv[KEY_LEN + IV_LEN];
        if (!derive_key(password, salt, key_iv, key_iv + KEY_LEN)) fail();
        
        unsigned char *decrypted = malloc(enc_size);
        size_t decrypted_size;
        if (!aes_decrypt(data + pos, enc_size, key_iv, key_iv + KEY_LEN, decrypted, &decrypted_size)) {
            free(decrypted);
            free(data);
            fail();
        }
        
        fwrite(decrypted, 1, decrypted_size, output);
        free(decrypted);
    } else {
        fwrite(data + data_start, 1, data_len - data_start, output);
    }
    
    fclose(output);
    free(data);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) fail();
    if (strcmp(argv[1], "hide") == 0 && argc == 5) return hide(argv[2], argv[3], argv[4]);
    else if (strcmp(argv[1], "decode") == 0 && argc == 4) return decode(argv[2], argv[3]);
    else fail();
}
