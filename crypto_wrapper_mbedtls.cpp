

#include <stdlib.h>
#include <string.h>
#include "crypto_wrapper.h"
#include "utils.h"
#ifdef MBEDTLS
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"


#ifdef WIN
#pragma comment (lib, "mbedtls.lib")
#endif // #ifdef WIN



static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
static constexpr size_t HASH_SIZE_BYTES			= 32;
static constexpr size_t IV_SIZE_BYTES			= 12;
static constexpr size_t GMAC_SIZE_BYTES			= 16;


int getRandom(void* contextData, BYTE* output, size_t len)
{
	if (!Utils::generateRandom(output, len))
	{
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}
	return (0);
}


bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, IN size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	const mbedtls_md_info_t* md_infoSha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (macBufferSizeBytes < mbedtls_md_get_size(md_infoSha256))
	{
		printf("mbedtls_md_hmac failed - output buffer too small!\n");
		return false;
	}

	int ret = mbedtls_md_hmac(md_infoSha256, key, keySizeBytes, message, messageSizeBytes, macBuffer);

	if (ret == 0)
	{
		return true;
	}
	return false;
}


bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	const mbedtls_md_info_t* mdSHA256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	int ret = mbedtls_hkdf(mdSHA256, salt, saltSizeBytes, secretMaterial, secretMaterialSizeBytes, context, contextSizeBytes, outputBuffer, outputBufferSizeBytes);
	
	if (ret == 0)
	{
		return true;
	}

	return false;
}


size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}


bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);

	if ((plaintext == NULL || plaintextSizeBytes == 0) && (aad == NULL || aadSizeBytes == 0))
	{
		return false;
	}

	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes == 0)
	{
		if (pCiphertextSizeBytes != NULL)
		{
			*pCiphertextSizeBytes = ciphertextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (ciphertextBufferSizeBytes < ciphertextSizeBytes)
	{
		return false;
	}

	// generate random IV 
	Utils::generateRandom(iv, IV_SIZE_BYTES);

	mbedtls_gcm_context gcm;

	mbedtls_gcm_init(&gcm);

	int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);            
	if (ret != 0)
	{
		printf("mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret);
		mbedtls_gcm_free(&gcm);
		return false;
	}

	ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintextSizeBytes, iv, IV_SIZE_BYTES, aad, aadSizeBytes, plaintext, ciphertextBuffer, GMAC_SIZE_BYTES, mac);

	if (ret != 0)
	{
		printf("mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned -0x%04x\n", -ret);
		mbedtls_gcm_free(&gcm);
		return false;
	}
	
	// append IV and GMAC to the ciphertextBuffer 
	memcpy(ciphertextBuffer + plaintextSizeBytes, iv, IV_SIZE_BYTES);
	memcpy(ciphertextBuffer + plaintextSizeBytes + IV_SIZE_BYTES, mac, GMAC_SIZE_BYTES);

	*pCiphertextSizeBytes = ciphertextSizeBytes;
	return true;
}


bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);
	
	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}
	
	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		return false;
	}

	if (pPlaintextSizeBytes != NULL)
	{
		*pPlaintextSizeBytes = plaintextSizeBytes;
	}

	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	BYTE *cipherBuffer = (BYTE *) malloc(plaintextSizeBytes);

	if (!cipherBuffer)
	{
		printf("error allocating memory\n");
		return false;
	}

	// extract ciphertext
	memcpy(cipherBuffer, ciphertext, plaintextSizeBytes);

	// extract the iv
	memcpy(iv, ciphertext + plaintextSizeBytes, IV_SIZE_BYTES);

	// extract the mac
	memcpy(mac, ciphertext + plaintextSizeBytes + IV_SIZE_BYTES, GMAC_SIZE_BYTES);
	mbedtls_gcm_context gcm;

	mbedtls_gcm_init(&gcm);

	int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
	if (ret != 0)
	{
		printf("mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret);
		mbedtls_gcm_free(&gcm);
		return false;
	}

	ret = mbedtls_gcm_auth_decrypt(&gcm, plaintextSizeBytes, iv, IV_SIZE_BYTES, aad, aadSizeBytes, mac, GMAC_SIZE_BYTES, cipherBuffer, plaintextBuffer);
	
	if (ret != 0)
	{
		printf("mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned -0x%04x\n", -ret);
		mbedtls_gcm_free(&gcm);
		return false;
	}

	free(cipherBuffer);
	return true;
}


bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	KeypairContext* newContext = (KeypairContext*)Utils::allocateBuffer(sizeof(KeypairContext));
	if (newContext == NULL)
	{
		printf("Error during memory allocation in readRSAKeyFromFile()\n");
		return false;
	}

	mbedtls_pk_init(newContext);
	ByteSmartPtr bufferSmartPtr = Utils::readBufferFromFile(keyFilename);
	if (bufferSmartPtr == NULL)
	{
		printf("Error reading keypair file\n");
		return false;
	}

	int res = mbedtls_pk_parse_key(newContext, bufferSmartPtr, bufferSmartPtr.size(), (const BYTE*)filePassword, strnlen_s(filePassword, MAX_PASSWORD_SIZE_BYTES), getRandom, NULL);
	if (res != 0)
	{
		printf("Error during mbedtls_pk_parse_key()\n");
		cleanKeyContext(&newContext);
		return false;
	}
	else
	{
		cleanKeyContext(pKeyContext);
		*pKeyContext = newContext;
		return true;
	}
}


bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	if (signatureBufferSizeBytes != SIGNATURE_SIZE_BYTES)
	{
		printf("Signature buffer size is wrong!\n");
		return false;
	}
	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*privateKeyContext);

	if ((mbedtls_rsa_check_privkey(rsa)) != 0)
	{
		printf("no private key\n");
		return false;
	}

	if ((mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256)) != 0)
	{
		printf("error in setting padding\n");
		return false;
	}
	
	if ((mbedtls_rsa_complete(rsa)) != 0)
	{
		printf("context is not complete\n");
		return false;
	}

	if ((mbedtls_rsa_rsassa_pss_sign(rsa, getRandom, NULL, MBEDTLS_MD_SHA256, 32, message, signatureBuffer)) != 0)
	{
		printf("error in signing message\n");
		return false;
	}
	return true;
}


bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
	if (signatureSizeBytes != SIGNATURE_SIZE_BYTES)
	{
		printf("Signature size is wrong!\n");
		return false;
	}

	int ret = 0;
	mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*publicKeyContext);

	if ((mbedtls_rsa_rsassa_pss_verify(rsa, MBEDTLS_MD_SHA256, 32, message, signature)) != 0)
	{
		return false;
	}
	*result = true;
	return true;
}


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		mbedtls_pk_free(*pKeyContext);
		Utils::freeBuffer(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN mbedtls_pk_context* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	memset(publicKeyPemBuffer, 0, publicKeyBufferSizeBytes);
	if (mbedtls_pk_write_pubkey_pem(keyContext, publicKeyPemBuffer, publicKeyBufferSizeBytes) != 0)
	{
		printf("Error during mbedtls_pk_write_pubkey_pem()\n");
		return false;
	}

	return true;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	mbedtls_pk_init(context);
	if (mbedtls_pk_parse_public_key(context, publicKeyPemBuffer, strnlen_s((const char*)publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES) + 1) != 0)
	{
		printf("Error during mbedtls_pk_parse_key() in loadPublicKeyFromPemBuffer()\n");
		return false;
	}
	return true;
}


bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	DhContext* dhContext = (DhContext*)Utils::allocateBuffer(sizeof(DhContext));
	if (dhContext == NULL)
	{
		printf("Error during memory allocation in startDh()\n");
		return false;
	}
	mbedtls_dhm_init(dhContext);

	mbedtls_mpi P;
	mbedtls_mpi G;
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&G);

	int ret = 0;

	const BYTE pBin[] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
	const BYTE gBin[] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

	// select the finite group modulus
	mbedtls_mpi_read_binary(&P, pBin, sizeof(pBin));

	// select the pre-agreed generator element of the finite group
	mbedtls_mpi_read_binary(&G, gBin, sizeof(gBin));

	if ((ret = mbedtls_dhm_set_group(dhContext, &P, &G)) != 0)
	{
		printf("error in setting P and G err: %d\n", ret);
		return false;
	}

	if ((ret = mbedtls_dhm_make_public(dhContext, DH_KEY_SIZE_BYTES, publicKeyBuffer, publicKeyBufferSizeBytes, getRandom, NULL)) != 0)
	{
		printf("error in making public key err: %d\n", ret);
		return false;
	}


	*pDhContext = dhContext;
	//cleanDhContext(&dhContext);
	return true;
}


bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
	int ret = mbedtls_dhm_read_public(dhContext, peerPublicKey, peerPublicKeySizeBytes);
	size_t olen = 0;
	if (ret != 0)
	{
		printf("error in read public err: %d\n", ret);
		return false;
	}

	ret = mbedtls_dhm_calc_secret(dhContext, sharedSecretBuffer, sharedSecretBufferSizeBytes, &olen, getRandom, NULL);

	if (ret != 0)
	{
		printf("error in calculating secret err: %d\n", ret);
		return false;
	}

	return true;
}


void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		mbedtls_dhm_free(*pDhContext);
		Utils::freeBuffer(*pDhContext);
		*pDhContext = NULL;
	}
}


bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt clicert;
	mbedtls_x509_crt_init(&cacert);
	mbedtls_x509_crt_init(&clicert);
	uint32_t flags;
	int res = -1;

	if (mbedtls_x509_crt_parse(&cacert, cACcertBuffer, cACertSizeBytes) != 0)
	{
		printf("Error parsing CA certificate\n");
		return false;
	}

	if (mbedtls_x509_crt_parse(&clicert, certBuffer, certSizeBytes) != 0)
	{
		printf("Error parsing certificate to verify\n");
		mbedtls_x509_crt_free(&cacert);
		return false;
	}

	res = mbedtls_x509_crt_verify(&clicert, &cacert, NULL, expectedCN, &flags, NULL, NULL);

	if (res != 0)
	{
		mbedtls_x509_crt_free(&cacert);
		mbedtls_x509_crt_free(&clicert);
		return false;
	}

	mbedtls_x509_crt_free(&cacert);
	mbedtls_x509_crt_free(&clicert);
	return true;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{
	BYTE publicKeyPemBuffer[PEM_BUFFER_SIZE_BYTES];

	mbedtls_x509_crt clicert;
	mbedtls_x509_crt_init(&clicert);

	if (mbedtls_x509_crt_parse(&clicert, certBuffer, certSizeBytes) != 0)
	{
		printf("Error parsing certificate to read\n");
		mbedtls_x509_crt_free(&clicert);
		return false;
	}
	
	KeypairContext* certPublicKeyContext = &(clicert.pk);
	// we will use a PEM buffer to create an independant copy of the public key context
	bool result = writePublicKeyToPemBuffer(certPublicKeyContext, publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES);
	mbedtls_x509_crt_free(&clicert);

	if (result)
	{
		KeypairContext* publicKeyContext = (KeypairContext*)Utils::allocateBuffer(sizeof(KeypairContext));
		if (publicKeyContext == NULL)
		{
			printf("Error during memory allocation in getPublicKeyFromCertificate()\n");
			return false;
		}

		if (loadPublicKeyFromPemBuffer(publicKeyContext, publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES))
		{
			cleanKeyContext(pPublicKeyContext);
			*pPublicKeyContext = publicKeyContext;
			return true;
		}
		else
		{
			cleanKeyContext(&publicKeyContext);
			return false;
		}
	}
	return false;
}

#endif // #ifdef MBEDTLS


/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://tls.mbed.org/api/gcm_8h.html
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* mbedtls_md_hmac
* mbedtls_hkdf
* mbedtls_gcm_setkey
* mbedtls_gcm_crypt_and_tag
* mbedtls_gcm_auth_decrypt
* mbedtls_md
* mbedtls_pk_get_type
* mbedtls_pk_rsa
* mbedtls_rsa_set_padding
* mbedtls_rsa_rsassa_pss_sign
* mbedtls_md_info_from_type
* mbedtls_rsa_rsassa_pss_verify
* mbedtls_dhm_set_group
* mbedtls_dhm_make_public
* mbedtls_dhm_read_public
* mbedtls_dhm_calc_secret
* mbedtls_x509_crt_verify
* 
* 
* 
* 
* 
* 
* 
*/