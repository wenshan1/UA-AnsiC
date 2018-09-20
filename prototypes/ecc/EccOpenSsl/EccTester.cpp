#include "stdafx.h"
#include "EccTester.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <memory.h>

using namespace msclr::interop;
using namespace System::IO;
using namespace System::Security::Cryptography;
using namespace System::Security::Cryptography::X509Certificates;
using namespace System::Runtime::InteropServices;

// #define EC_CURVE_NAME SN_X9_62_prime256v1
#define EC_CURVE_NAME SN_brainpoolP256r1

struct _OpcUa_ByteString
{
	unsigned int Length;
	unsigned char* Data;
};

typedef struct _OpcUa_ByteString OpcUa_ByteString;

struct _OpcUa_Key
{
	unsigned int Type;
	OpcUa_ByteString Key;
};

typedef struct _OpcUa_Key OpcUa_Key;

static String^ FormatHexString(OpcUa_ByteString& bytes, int offset = 0, int length = -1)
{
	if (length < 0)
	{
		length = bytes.Length;
	}

	auto buffer = gcnew System::Text::StringBuilder();

	for (int ii = offset; ii < offset + length; ii++)
	{
		buffer->AppendFormat("{0:X2}", bytes.Data[ii]);
	}

	return buffer->ToString();
}

static void PrintHexString(String^ text, OpcUa_ByteString& bytes, int offset = 0, int length = -1)
{
	Console::WriteLine(text + " {0}", FormatHexString(bytes, offset, length));
}

bool LoadCertificate(const char* filePath, OpcUa_ByteString* pCertificate)
{
	pCertificate->Length = 0;
	pCertificate->Data = nullptr;

	auto pFile = BIO_new_file(filePath, "rb");

	if (pFile == nullptr)
	{
		return false;
	}

	auto pX509 = d2i_X509_bio(pFile, (X509**)nullptr);

	if (pX509 == nullptr)
	{
		BIO_free(pFile);
		return false;
	}

	BIO_free(pFile);
	pFile = nullptr;

	pCertificate->Length = i2d_X509(pX509, NULL);
	auto pBuffer = pCertificate->Data = new unsigned char[pCertificate->Length];
	auto pos = pBuffer;
	
	auto result = i2d_X509(pX509, &pos);

	if (result != pCertificate->Length)
	{
		X509_free(pX509);
		return false;
	}

	X509_free(pX509);
	pX509 = nullptr;

	return true;
}

bool LoadPrivateKey(const char* filePath, const char* password, OpcUa_ByteString* pPrivateKey)
{
	pPrivateKey->Length = 0;
	pPrivateKey->Data = nullptr;

	auto pFile = BIO_new_file(filePath, "rb");

	if (pFile == nullptr)
	{
		return false;
	}

	auto pEvpKey = PEM_read_bio_PrivateKey(pFile, NULL, 0, (void*)password);

	if (pEvpKey == nullptr)
	{
		BIO_free(pFile);
		return false;
	}

	BIO_free(pFile);
	pFile = nullptr;

	auto pEcPrivateKey = EVP_PKEY_get1_EC_KEY(pEvpKey);

	if (pEcPrivateKey == nullptr)
	{
		EVP_PKEY_free(pEvpKey);
		return false;
	}

	EVP_PKEY_free(pEvpKey);
	pEvpKey = nullptr;

	pPrivateKey->Length = i2d_ECPrivateKey(pEcPrivateKey, nullptr);
	pPrivateKey->Data = new unsigned char[pPrivateKey->Length];

	auto pData = pPrivateKey->Data;
	int result = i2d_ECPrivateKey(pEcPrivateKey, &pData);

	if (result != pPrivateKey->Length)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	EC_KEY_free(pEcPrivateKey);

	return true;
}

bool VerifySignature(
	OpcUa_ByteString* pData,
	OpcUa_ByteString* pCertificate)
{
	const unsigned char* pos = pCertificate->Data;

	auto pX509 = d2i_X509((X509**)nullptr, &pos, pCertificate->Length);

	if (pX509 == nullptr)
	{
		return false;
	}

	auto pX509PublicKey = X509_get_pubkey(pX509);

	if (pX509PublicKey == nullptr)
	{
		X509_free(pX509);
		return false;
	}

	auto pEcPublicKey = EVP_PKEY_get1_EC_KEY(pX509PublicKey);

	if (pEcPublicKey == nullptr)
	{
		X509_free(pX509);
		return false;
	}

	X509_free(pX509);
	pX509 = nullptr;

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPublicKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	OpcUa_ByteString signature;
	signature.Length = keySize*2;
	signature.Data = pData->Data + pData->Length - keySize*2;

	auto pEcSignature = ECDSA_SIG_new();

	if (pEcSignature == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	auto r = BN_bin2bn(signature.Data, keySize, nullptr);

	if (r == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	auto s = BN_bin2bn(signature.Data + keySize, keySize, nullptr);

	if (s == nullptr)
	{
		BN_free(r);
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	BN_free(pEcSignature->r);
	BN_free(pEcSignature->s);
	pEcSignature->r = r;
	pEcSignature->s = s;

	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (::SHA256(pData->Data, pData->Length - keySize*2, digest) == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	if (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, pEcSignature, pEcPublicKey) != 1)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	ECDSA_SIG_free(pEcSignature);
	EC_KEY_free(pEcPublicKey);

	return true;
}

#define bn2bin_pad(bn,to,len)                           \
    do {                                                \
        int pad_len = (len) - BN_num_bytes(bn);         \
        memset(to, 0, pad_len);                   \
        BN_bn2bin(bn, (to) + pad_len);                  \
    } while(0)

bool CreateSignature(
	OpcUa_ByteString* pData,
	OpcUa_ByteString* pPrivateKey,
	OpcUa_ByteString* pSignature)
{
	const unsigned char* pos = pPrivateKey->Data;

	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pos, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return false;
	}

	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (::SHA256(pData->Data, pData->Length, digest) == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pEcSignature = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, pEcPrivateKey);

	if (pEcSignature == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	pSignature->Length = keySize * 2;
	pSignature->Data = new unsigned char[pSignature->Length];

	bn2bin_pad(pEcSignature->r, pSignature->Data, keySize);
	bn2bin_pad(pEcSignature->s, pSignature->Data + keySize, keySize);

	ECDSA_SIG_free(pEcSignature);
	EC_KEY_free(pEcPrivateKey);

	return true;
}

unsigned int GetSignatureSize(OpcUa_ByteString* pPrivateKey)
{
	const unsigned char* pos = pPrivateKey->Data;

	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pos, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return 0;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return 0;
	}

	keySize = (keySize + 7) / 8;
	EC_KEY_free(pEcPrivateKey);

	return keySize * 2;
}

static unsigned int DecodeUInt32(unsigned char* data, unsigned int offset, unsigned int length)
{
	if (data == nullptr || length < offset + 4)
	{
		return -1;
	}

	unsigned int value = data[offset];

	value += (((unsigned int)data[offset+1]) << 8);
	value += (((unsigned int)data[offset+2]) << 16);
	value += (((unsigned int)data[offset+3]) << 24);

	return value;
}

static void EncodeUInt32(unsigned int value, unsigned char* data, unsigned int offset, unsigned int length)
{
	if (data == nullptr || length < 4)
	{
		throw gcnew ArgumentException("length");
	}

	data[offset] = (unsigned char)(value & 0x000000FF);
	data[offset + 1] = (unsigned char)((value & 0x0000FF00) >> 8);
	data[offset + 2] = (unsigned char)((value & 0x00FF0000) >> 16);
	data[offset + 3] = (unsigned char)((value & 0xFF000000) >> 24);
}

static OpcUa_ByteString Copy(OpcUa_ByteString& src)
{
	OpcUa_ByteString dst;
	dst.Length = src.Length;
	dst.Data = new unsigned char[dst.Length];
	memcpy(dst.Data, src.Data, dst.Length);
	return dst;
}

static bool Decode(
	unsigned char* data, 
	unsigned int offset, 
	unsigned int length, 
	OpcUa_ByteString* pSenderCertificate, 
	OpcUa_ByteString* pSenderEphemeralKey)
{
	auto totalLength = DecodeUInt32(data, offset, length);
	
	OpcUa_ByteString message;
	message.Data = data + offset;
	message.Length = totalLength;
	offset += 4;

	auto signingCertificateLength = DecodeUInt32(data, offset, length - offset);
	offset += 4;

	auto pSigningCertificateData = data + offset;
	offset += signingCertificateLength;

	OpcUa_ByteString certificate;
	certificate.Length = signingCertificateLength;
	certificate.Data = pSigningCertificateData;

	auto senderKeyLength = DecodeUInt32(data, offset, length - offset);
	offset += 4;

	auto pSenderKeyData = data + offset;
	offset += senderKeyLength;

	OpcUa_ByteString senderKey;
	senderKey.Length = senderKeyLength;
	senderKey.Data = pSenderKeyData;

	if (!VerifySignature(&message, &certificate))
	{
		return false;
	}

	*pSenderCertificate = Copy(certificate);
	*pSenderEphemeralKey = Copy(senderKey);

	// PrintHexString("CLIENT EKEY", *pSenderEphemeralKey);
	return true;
}

static bool Encode(
	OpcUa_ByteString* pSenderCertificate,
	OpcUa_ByteString* pSenderPrivateKey,
	OpcUa_ByteString* pSenderEphemeralKey,
	OpcUa_ByteString* pMessage)
{
	auto totalLength = 12;
	totalLength += pSenderCertificate->Length;
	totalLength += pSenderEphemeralKey->Length;
	totalLength += GetSignatureSize(pSenderPrivateKey);

	pMessage->Length = totalLength;
	pMessage->Data = new unsigned char[totalLength];

	auto offset = 0;
	EncodeUInt32(totalLength, pMessage->Data, offset, pMessage->Length - offset);

	offset += 4;
	EncodeUInt32(pSenderCertificate->Length, pMessage->Data, offset, pMessage->Length - offset);

	offset += 4;
	memcpy(pMessage->Data + offset, pSenderCertificate->Data, pSenderCertificate->Length);

	offset += pSenderCertificate->Length;
	EncodeUInt32(pSenderEphemeralKey->Length, pMessage->Data, offset, pMessage->Length - offset);

	offset += 4;
	memcpy(pMessage->Data + offset, pSenderEphemeralKey->Data, pSenderEphemeralKey->Length);

	offset += pSenderEphemeralKey->Length;

	OpcUa_ByteString message;
	message.Data = pMessage->Data;
	message.Length = offset;

	OpcUa_ByteString signature;
	signature.Data = nullptr;
	signature.Length = 0;

	if (!CreateSignature(&message, pSenderPrivateKey, &signature))
	{
		delete[] pMessage->Data;
		pMessage->Data = nullptr;
		pMessage->Length = 0;
		return false;
	}

	memcpy(pMessage->Data + offset, signature.Data, signature.Length);
	delete[] signature.Data;

	return true;
}

bool GenerateKeys(
	const char* curveName,
	OpcUa_ByteString* pPublicKey,
	OpcUa_ByteString* pPrivateKey)
{
	pPublicKey->Length = 0;
	pPublicKey->Data = nullptr;

	pPrivateKey->Length = 0;
	pPrivateKey->Data = nullptr;

	int curveId = 0;

	if (strcmp(SN_X9_62_prime256v1, curveName) == 0) { curveId = NID_X9_62_prime256v1; }
	if (strcmp(SN_brainpoolP256r1, curveName) == 0) { curveId = NID_brainpoolP256r1; }

	auto pEcKey = EC_KEY_new_by_curve_name(curveId);

	if (pEcKey == nullptr)
	{
		return false;
	}

	if (EC_KEY_generate_key(pEcKey) == 0)
	{
		EC_KEY_free(pEcKey);
		return false;
	}

	pPrivateKey->Length = i2d_ECPrivateKey(pEcKey, NULL);

	if (pPrivateKey->Length == 0)
	{
		EC_KEY_free(pEcKey);
		return false;
	}

	pPrivateKey->Data = new unsigned char[pPrivateKey->Length];

	if (pPrivateKey->Data == nullptr)
	{
		EC_KEY_free(pEcKey);
		return false; 
	}

	auto pData = pPrivateKey->Data;
	pPrivateKey->Length = i2d_ECPrivateKey(pEcKey, &pData);

	if (pPrivateKey->Length == 0)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcKey));

	if (keySize == 0)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	pPublicKey->Length = keySize * 2;
	pPublicKey->Data = new unsigned char[pPublicKey->Length];

	if (pPublicKey->Data == nullptr)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto pCtx = BN_CTX_new();

	if (pCtx == nullptr)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		delete[] pPublicKey->Data;
		pPublicKey->Data = nullptr;
		pPublicKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto x = BN_CTX_get(pCtx);
	auto y = BN_CTX_get(pCtx);

	auto point = EC_KEY_get0_public_key(pEcKey);

	if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcKey), point, x, y, pCtx))
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		delete[] pPublicKey->Data;
		pPublicKey->Data = nullptr;
		pPublicKey->Length = 0;
		EC_KEY_free(pEcKey);
		BN_CTX_free(pCtx);
		return false;
	}

	bn2bin_pad(x, pPublicKey->Data, keySize);
	bn2bin_pad(y, pPublicKey->Data + keySize, keySize);

	BN_CTX_free(pCtx);
	EC_KEY_free(pEcKey);
	return true;
}

bool CreateNonce(unsigned int length, OpcUa_ByteString* pNonce)
{
	pNonce->Length = length;
	pNonce->Data = new unsigned char[length];

	if (RAND_bytes(pNonce->Data, length) <= 0)
	{
		delete[] pNonce->Data;
		pNonce->Length = 0;
		pNonce->Data = nullptr;
		return false;
	}

	return true;
}

bool ComputeSecret(
	OpcUa_ByteString* pNonce,
	OpcUa_ByteString* pPrivateKey,
	OpcUa_ByteString* pSalt,
	OpcUa_ByteString* pSharedSecret)
{
	const unsigned char* pData = pPrivateKey->Data;
	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pData, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	if (pNonce->Length != 2 * keySize)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pCtx = BN_CTX_new();

	if (pCtx == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto x = BN_CTX_get(pCtx);
	auto y = BN_CTX_get(pCtx);

	x = BN_bin2bn(pNonce->Data, keySize, x);

	if (x == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	y = BN_bin2bn(pNonce->Data + keySize, keySize, y);

	if (y == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto p1 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));

	if (p1 == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey), p1, x, y, pCtx))
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto p2 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));

	if (p2 == nullptr)
	{
		EC_POINT_free(p1);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_mul(EC_KEY_get0_group(pEcPrivateKey), p2, NULL, p1, EC_KEY_get0_private_key(pEcPrivateKey), pCtx))
	{
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey), p2, x, y, pCtx))
	{
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pKeyMaterial = new unsigned char[keySize];
	memset(pKeyMaterial, 0, keySize);
	bn2bin_pad(x, pKeyMaterial, keySize);

	int hmacKeySize = (pSalt->Length < SHA256_DIGEST_LENGTH) ? SHA256_DIGEST_LENGTH : pSalt->Length;
	auto pHmacKey = new unsigned char[hmacKeySize];
	memset(pHmacKey, 0, hmacKeySize);
	memcpy(pHmacKey, pSalt->Data, pSalt->Length);

	pSharedSecret->Length = SHA256_DIGEST_LENGTH;
	pSharedSecret->Data = new unsigned char[SHA256_DIGEST_LENGTH];

	if (::HMAC(EVP_sha256(), pHmacKey, hmacKeySize, pKeyMaterial, keySize, pSharedSecret->Data, nullptr) == nullptr)
	{
		delete[] pSharedSecret->Data;
		pSharedSecret->Data = nullptr;
		pSharedSecret->Length = 0;
		delete[] pKeyMaterial;
		delete[] pHmacKey;
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	/*
	if (::SHA256(pBuffer, keySize, pSharedSecret->Data) == nullptr)
	{
		delete[] pSharedSecret->Data;
		pSharedSecret->Data = nullptr;
		pSharedSecret->Length = 0;
		delete[] pBuffer;
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}
	*/

	delete[] pKeyMaterial;
	delete[] pHmacKey;
	EC_POINT_free(p1);
	EC_POINT_free(p2);
	BN_CTX_free(pCtx);
	EC_KEY_free(pEcPrivateKey);

	return true;
}

static bool DeriveKeys(OpcUa_ByteString* pSecret, OpcUa_ByteString* pSeed, unsigned int length, OpcUa_ByteString* pKeys)
{
	//PrintHexString("SSL: SECRET: ", *pSecret);
	//PrintHexString("SSL: SEED: ", *pSeed);

	// calculate T(1)
	int counter = 1;

	int infoLength = SHA256_DIGEST_LENGTH + pSeed->Length + 1;
	auto pInfo = new unsigned char[infoLength];
	memset(pInfo, 0, infoLength);
	memcpy(pInfo, pSeed->Data, pSeed->Length);
	pInfo[pSeed->Length] = counter++;

	unsigned int hashLength = SHA256_DIGEST_LENGTH;
	auto pHash = new unsigned char[hashLength];

	if (::HMAC(EVP_sha256(), pSecret->Data, pSecret->Length, pInfo, pSeed->Length+1, pHash, nullptr) == nullptr)
	{
		delete[] pHash;
		delete[] pInfo;
		return false;
	}

	// create buffer with requested size.
	auto pOutput = new unsigned char[length];

	unsigned int position = 0;

	for (unsigned int ii = 0; position < length && ii < hashLength; ii++)
	{
		pOutput[position++] = pHash[ii];
	}

	// calculate T(n)
	while (position < length)
	{
		memcpy(pInfo, pHash, SHA256_DIGEST_LENGTH);
		memcpy(pInfo + SHA256_DIGEST_LENGTH, pSeed->Data, pSeed->Length);
		pInfo[infoLength - 1] = counter++;

		if (::HMAC(EVP_sha256(), pSecret->Data, pSecret->Length, pInfo, infoLength, pHash, nullptr) == nullptr)
		{
			delete[] pInfo;
			delete[] pHash;
			delete[] pOutput;
			return false;
		}

		for (unsigned int ii = 0; position < length && ii < hashLength; ii++)
		{
			pOutput[position++] = pHash[ii];
		}
	} 

	delete[] pInfo;
	delete[] pHash;

	pKeys->Data = pOutput;
	pKeys->Length = length;

	return true;
}

static bool AreEqual(OpcUa_ByteString& value1, OpcUa_ByteString& value2)
{
	if (value2.Length != value1.Length)
	{
		return false;
	}

	for (auto ii = 0U; ii < value1.Length; ii++)
	{
		if (value1.Data[ii] != value2.Data[ii])
		{
			return false;
		}
	}

	return true;
}

namespace EccOpenSsl {

	class EccTesterData
	{
	public:

		EccTesterData()
		{
			memset(&Certificate, 0, sizeof(OpcUa_ByteString));
			memset(&PrivateKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPublicKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPrivateKey, 0, sizeof(OpcUa_ByteString));
		}

		~EccTesterData()
		{
			if (Certificate.Data != nullptr)
			{
				delete[] Certificate.Data;
			}

			if (PrivateKey.Data != nullptr)
			{
				delete[] PrivateKey.Data;
			}

			if (EphemeralPublicKey.Data != nullptr)
			{
				delete[] EphemeralPublicKey.Data;
			}

			if (EphemeralPrivateKey.Data != nullptr)
			{
				delete[] EphemeralPrivateKey.Data;
			}
		}

		OpcUa_ByteString Certificate;
		OpcUa_ByteString PrivateKey;
		OpcUa_ByteString EphemeralPublicKey;
		OpcUa_ByteString EphemeralPrivateKey;
	};

	EccTester::EccTester()
	{
		m_p = new EccTesterData();
	}

	EccTester::~EccTester()
	{
		delete m_p;
	}

	void EccTester::SetLocalCertificate(String^ certificateFilePath, String^ privateKeyFilePath, String^ password)
	{
		marshal_context context;
		auto pFilePath = context.marshal_as<const char*>(certificateFilePath);

		if (!LoadCertificate(pFilePath, &m_p->Certificate))
		{
			throw gcnew ArgumentException("certificateFilePath");
		}

		pFilePath = context.marshal_as<const char*>(privateKeyFilePath);
		auto pPassword = (password != nullptr) ? context.marshal_as<const char*>(password) : nullptr;

		if (!LoadPrivateKey(pFilePath, pPassword, &m_p->PrivateKey))
		{
			throw gcnew ArgumentException("privateKeyFilePath");
		}
	}

	void EccTester::Decode(String^ requestPath, String^ responsePath, array<unsigned char>^% clientSecret, array<unsigned char>^% serverSecret)
	{
		auto bytes = File::ReadAllBytes(requestPath);

		auto message = new unsigned char[bytes->Length];

		OpcUa_ByteString clientCertificate = { 0, 0 };
		OpcUa_ByteString clientEphemeralPublicKey = { 0, 0 };
		OpcUa_ByteString response = { 0, 0 };
		OpcUa_ByteString localClientSecret = { 0, 0 };
		OpcUa_ByteString localServerSecret = { 0, 0 };
		OpcUa_ByteString derivedKeys = { 0, 0 };

		try
		{
			Marshal::Copy(bytes, 0, (IntPtr)message, bytes->Length);

			if (!::Decode(message, 0, bytes->Length, &clientCertificate, &clientEphemeralPublicKey))
			{
				throw gcnew ArgumentException("messagePath");
			}

			if (!GenerateKeys(EC_CURVE_NAME, &m_p->EphemeralPublicKey, &m_p->EphemeralPrivateKey))
			{
				throw gcnew ArgumentException("generateKeys");
			}

			PrintHexString("SSL: CLIENT SECRET HMAC KEY: ", m_p->EphemeralPublicKey);

			if (!ComputeSecret(&clientEphemeralPublicKey, &m_p->EphemeralPrivateKey, &m_p->EphemeralPublicKey, &localClientSecret))
			{
				throw gcnew ArgumentException("computeSecret");
			}

			PrintHexString("SSL: ClientSecret: ", localClientSecret);

			PrintHexString("SSL: SERVER SECRET HMAC KEY: ", clientEphemeralPublicKey);

			if (!ComputeSecret(&clientEphemeralPublicKey, &m_p->EphemeralPrivateKey, &clientEphemeralPublicKey, &localServerSecret))
			{
				throw gcnew ArgumentException("computeSecret");
			}

			PrintHexString("SSL: ServerSecret: ", localServerSecret);

			if (!DeriveKeys(&localServerSecret, &localClientSecret, 80, &derivedKeys))
			{
				throw gcnew ArgumentException("deriveKeys");
			}

			Console::WriteLine("==== SSL Derived Keys ====");
			PrintHexString("SSL: ServerSigningKey: ", derivedKeys, 0, 32);
			PrintHexString("SSL: ServerEncryptingKey: ", derivedKeys, 32, 32);
			PrintHexString("SSL: ServerInitializationVector: ", derivedKeys, 64, 16);

			delete [] derivedKeys.Data;

			if (!DeriveKeys(&localClientSecret, &localServerSecret, 80, &derivedKeys))
			{
				throw gcnew ArgumentException("deriveKeys");
			}

			PrintHexString("SSL: ClientSigningKey: ", derivedKeys, 0, 32);
			PrintHexString("SSL: ClientEncryptingKey: ", derivedKeys, 32, 32);
			PrintHexString("SSL: ClientInitializationVector: ", derivedKeys, 64, 16);
			
			if (!::Encode(&m_p->Certificate, &m_p->PrivateKey, &m_p->EphemeralPublicKey, &response))
			{
				throw gcnew ArgumentException("encode");
			}

			bytes = gcnew array<unsigned char>(response.Length);
			Marshal::Copy((IntPtr)response.Data, bytes, 0, bytes->Length);
			File::WriteAllBytes(responsePath, bytes);

			clientSecret = gcnew array<unsigned char>(localClientSecret.Length);
			Marshal::Copy((IntPtr)localClientSecret.Data, clientSecret, 0, clientSecret->Length);

			serverSecret = gcnew array<unsigned char>(localServerSecret.Length);
			Marshal::Copy((IntPtr)localServerSecret.Data, serverSecret, 0, serverSecret->Length);
		}
		finally
		{
			delete[] message;
			delete[] clientCertificate.Data;
			delete[] clientEphemeralPublicKey.Data;
			delete[] localClientSecret.Data;
			delete[] localServerSecret.Data;
		}
	}

	void EccTester::Encode(String^ certificateFilePath, String^ privateKeyFilePath, String^ password)
	{
		marshal_context context;
		auto pFilePath = context.marshal_as<const char*>(certificateFilePath);

		OpcUa_ByteString certificate;
		OpcUa_ByteString privateKey;

		if (!LoadCertificate(pFilePath, &certificate))
		{
			throw gcnew ArgumentException("keyFilePath");
		}

		pFilePath = context.marshal_as<const char*>(privateKeyFilePath);
		auto pPassword = (password != nullptr) ? context.marshal_as<const char*>(password) : nullptr;

		if (!LoadPrivateKey(pFilePath, pPassword, &privateKey))
		{
			throw gcnew ArgumentException("keyFilePath");
		}
	}

	void EccTester::Initialize()
	{
		OpenSSL_add_all_algorithms();
		RAND_screen();
		SSL_library_init();
		SSL_load_error_strings();
	}

	void EccTester::Cleanup()
	{
		SSL_COMP_free_compression_methods();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_state(0);
		ERR_free_strings();
	}
}