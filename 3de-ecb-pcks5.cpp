// sign-demo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include<string.h>

void handleErrors(void);
char* encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, int* base64TextLength);
int decrypt(char* ciphertext, unsigned char* key, unsigned char* plaintext);
void Base64Encode(const unsigned char* buffer,
    size_t length, char** base64Text);
size_t calcDecodeLength(const char* b64input);
void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);

int main(void)
{

    unsigned char* key = (unsigned char*)"60801abac4662824895d9646";

    /* Message to be encrypted */
    unsigned char* plaintext =
        (unsigned char*)"appId=100854&channel=5&msgId=1652839608744&orgId=10142&timestamp=2022-05-18 10:06";

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128 * 8];
    memset(decryptedtext, '/0', 128 * 8);
    int ciphertextLen;

    /* Encrypt the plaintext */
    char* base64Text = encrypt(plaintext, strlen((char*)plaintext), key, &ciphertextLen);
    std::cout << base64Text << std::endl;

    int decLen  = decrypt(base64Text, key, decryptedtext);
    decryptedtext[decLen] = '\0';
    std::cout << decryptedtext << std::endl;
    std::cout << decLen << std::endl;

    return 0;
}

void Base64Encode(const unsigned char* buffer,
    size_t length,
    char** base64Text) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());

    // 控制 base64 输出字符串不换行
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *base64Text = (*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') //last char is =
        padding = 1;
    return (len * 3) / 4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO* bio, * b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());

    // 控制 base64 输出字符串不换行
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

char* encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, int* base64TextLength)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    char* base64Text;

    int ciphertext_len;
    unsigned char ciphertext[128 * 8];
    memset(ciphertext, '\0', 128 * 8);

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }    

    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, (unsigned char *)""))
        handleErrors();


    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }
        
    ciphertext_len = len;    

    //EVP_PADDING_PKCS7 兼容 PKCS5
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handleErrors();
    }

    ciphertext_len += len;
    ciphertext[ciphertext_len] = '\0';
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    Base64Encode(ciphertext, ciphertext_len, &base64Text);
    return base64Text;
}


int decrypt(char* ciphertext, unsigned char* key, unsigned char* plaintext)
{
    unsigned char* encMessage;
    size_t encMessageLength;
    Base64Decode(ciphertext, &encMessage, &encMessageLength);
    EVP_CIPHER_CTX* ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, (unsigned char*)""))
        handleErrors();

    //EVP_PADDING_PKCS7 兼容 PKCS5
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);


    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, encMessage, encMessageLength))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
