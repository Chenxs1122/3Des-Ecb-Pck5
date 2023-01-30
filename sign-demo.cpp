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
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include<string.h>
#define GETCH() getchar()

#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")

void handleErrors(void);
char* encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
	unsigned char* iv, int* base64TextLength);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
	unsigned char* iv, unsigned char* plaintext);
void Base64Encode(const unsigned char* buffer,
	size_t length, char** base64Text);

int main(void)
{
	/*
	 * Set up the key and iv. Do I need to say to not hard code these in a
	 * real application? :-)
	 */

	 /* A 256 bit key */
	unsigned char* key = (unsigned char*)"60801abac4662824895d9646";

	/* Message to be encrypted */
	unsigned char* plaintext =
		(unsigned char*)"appId=100854&channel=5&msgId=1652839608744&orgId=10142&timestamp=2022-05-18 10:06";

	/* Buffer for the decrypted text */
	unsigned char decryptedtext[128 * 8];
	memset(decryptedtext, 'v', 128 * 8);


	int decryptedtext_len, ciphertext_len;

	/* Encrypt the plaintext */
	char* base64Text = encrypt(plaintext, strlen((char*)plaintext), key, (unsigned char*)"",
		&ciphertext_len);
	std::cout << base64Text << std::endl;

	///* Do something useful with the ciphertext here */
	//printf("Ciphertext is:\n");
	//BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);

	///* Decrypt the ciphertext */
	//decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, (unsigned char*)"",
	//	decryptedtext);

	///* Add a NULL terminator. We are expecting printable text */
	//decryptedtext[decryptedtext_len] = '\0';

	///* Show the decrypted text */
	//printf("Decrypted text is:\n");
	//printf("%s\n", decryptedtext);


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


void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

char* encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
	unsigned char* iv, int* base64TextLength)
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


	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, iv))
		handleErrors();


	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		handleErrors();
	}
		
	ciphertext_len = len;	

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


int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
	unsigned char* iv, unsigned char* plaintext)
{
	EVP_CIPHER_CTX* ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/*
	 *
	 *
	 */
	EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_ZERO);

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary.
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/*
	 * Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);



	return plaintext_len;
}


/*
int Base64Encode(unsigned char* pIn, unsigned char* pOut, int nInLen)
{
	char base64tab[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned char c1, c2, c3;
	int nInPos = 0;
	int nOutPos = 0;
	int i;

	for (i = 0; i < nInLen / 3; i++)
	{
		c1 = pIn[nInPos++];
		c2 = pIn[nInPos++];
		c3 = pIn[nInPos++];

		pOut[nOutPos++] = base64tab[(c1 & '\xFC') >> 2];
		pOut[nOutPos++] = base64tab[((c1 & '\x03') << 4) | ((c2 & '\xF0') >> 4)];
		pOut[nOutPos++] = base64tab[((c2 & '\x0F') << 2) | ((c3 & '\xC0') >> 6)];
		pOut[nOutPos++] = base64tab[c3 & '\x3F'];
	}

	if (nInLen % 3 == 1)
	{
		c1 = pIn[nInPos++];
		pOut[nOutPos++] = base64tab[(c1 & '\xFC') >> 2];
		pOut[nOutPos++] = base64tab[((c1 & '\x03') << 4)];
		pOut[nOutPos++] = '=';
		pOut[nOutPos++] = '=';
	}
	else if (nInLen % 3 == 2)
	{
		c1 = pIn[nInPos++];
		c2 = pIn[nInPos++];
		pOut[nOutPos++] = base64tab[(c1 & '\xFC') >> 2];
		pOut[nOutPos++] = base64tab[((c1 & '\x03') << 4) | ((c2 & '\xF0') >> 4)];
		pOut[nOutPos++] = base64tab[((c2 & '\x0F') << 2)];
		pOut[nOutPos++] = '=';
	}

	pOut[nOutPos] = '\0';
	return nOutPos;
}
bool Encrypt(unsigned char* key, unsigned char* iv, char* strInput, char* strOutput)
{
	unsigned char sCipher[4096];	//密文缓冲区
	int nCipher;					//密文长度
	int nTmp;
	int rv;
	unsigned char sBase64[4096];

	//初始化密码算法结构体
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	//设置算法和密钥
	rv = EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, iv);
	if (rv != 1)
		return true;
	//数据加密
	rv = EVP_EncryptUpdate(ctx, sCipher, &nCipher, (const unsigned char *)strInput, strlen(strInput));
	if (rv != 1)
		return true;
	//结束数据加密，把剩余数据输出
	rv = EVP_EncryptFinal_ex(ctx, sCipher + nCipher, &nTmp);
	if (rv != 1)
		return true;
	nCipher = nCipher + nTmp;
	sCipher[nCipher] = '\0';
	//可视化输出base64
	Base64Encode(sCipher, sBase64, nCipher);
	sprintf(strOutput, "%s", sBase64);
	EVP_CIPHER_CTX_cleanup(ctx);
	return false;
}

int main()
{
	char strTmp[1024] = { 0 };
	char strInput[1024] = "appId=100854&channel=5&msgId=1652839608744&orgId=10142&timestamp=2022-05-18 10:06";
	char key[30] = "60801abac4662824895d9646";
	Encrypt((unsigned char*)key, (unsigned char*)"", strInput, strTmp);
	printf("Result:%s\n", strTmp);
	//system("pause");
	return 0;
}*/

//void Base64Encode(const unsigned char* buffer,
//    size_t length,
//    char** base64Text) {
//    BIO* bio, * b64;
//    BUF_MEM* bufferPtr;
//
//    b64 = BIO_new(BIO_f_base64());
//
//    // 控制 base64 输出字符串不换行
//    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//
//    bio = BIO_new(BIO_s_mem());
//    bio = BIO_push(b64, bio);
//
//    BIO_write(bio, buffer, length);
//    BIO_flush(bio);
//    BIO_get_mem_ptr(bio, &bufferPtr);
//    BIO_set_close(bio, BIO_NOCLOSE);
//    BIO_free_all(bio);
//
//    *base64Text = (*bufferPtr).data;
//}
//
//
//int main() {
//    unsigned char intext[256], outtext[256];
//
//    memset(intext, 0x07, sizeof(intext)); //PKCS#5 padding 
//    memset(outtext, 0, sizeof(outtext));
//    char* output;
//
//    DES_key_schedule keyschedc1;
//    DES_key_schedule keyschedc2;
//    DES_key_schedule keyschedc3;
//    DES_cblock keyc1;
//    DES_cblock keyc2;
//    DES_cblock keyc3;
//
//    DES_set_key((DES_cblock*)"abcdefgh", &keyschedc1);
//    DES_set_key((DES_cblock*)"ijklmnop", &keyschedc2);
//    DES_set_key((DES_cblock*)"qrstuvwx", &keyschedc3);
//
//    strcpy((char*)intext, "holahola1");
//
//    for (int i = 0; i < 16; i += 8)
//    {
//        DES_ecb3_encrypt((DES_cblock*)(intext + i),
//            (DES_cblock*)(outtext + i),
//            &keyschedc1, &keyschedc2,
//            &keyschedc3, DES_ENCRYPT);
//    }
//
//    Base64Encode(outtext, 16, &output);
//    std::cout << output << std::endl;
//
//    return 0;
//}

//int main() {
//	OpenSSL_add_all_algorithms();
//	EVP_MD_CTX* mdctx;
//	const EVP_MD* md;
//	char mess1[] = "abc";
//	printf("%d", sizeof(mess1));
//	unsigned char md_value[EVP_MAX_MD_SIZE] = { 0 };
//	int md_len, i;
//
//	md = EVP_get_digestbyname("sm3");
//
//	if (!md) {
//		return -1;
//	}
//
//	mdctx = EVP_MD_CTX_new(); //分配、初始化并返回摘要上下文.
//	EVP_DigestInit_ex(mdctx, md, NULL);  //设置摘要上下文ctx以使用ENGINE impl中的摘要类型. 
//	EVP_DigestUpdate(mdctx, mess1, strlen(mess1)); //将d处的cnt字节数据散列到摘要上下文ctx中.
//	EVP_DigestFinal_ex(mdctx, md_value, (unsigned int*)&md_len);//从ctx检索摘要值并将其存入md中. 
//	EVP_MD_CTX_free(mdctx);
//
//	printf("sm3 Digest is: \n");
//	for (i = 0; i < md_len; i++) {
//		printf("%02x", md_value[i]);
//		if (i % 16 == 15) {
//			//printf("\n");
//		}
//	}
//	printf("\n");
//	printf("\n按任意键继续...");
//	GETCH();
//
//	return 0;
//}
