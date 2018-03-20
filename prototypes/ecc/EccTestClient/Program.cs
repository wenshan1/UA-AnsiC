// #define nistP256
#define brainpoolP256r1

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Numerics;
using Opc.Ua;

namespace EccTestClient
{
    class Program
    {
        #if nistP256
        static ECCurve CurveToUse = ECCurve.NamedCurves.nistP256;
        static string ClientCertificate = "Charlie";
        static string ServerCertificate = "Diana";
        # elif brainpoolP256r1
        static ECCurve CurveToUse = ECCurve.NamedCurves.brainpoolP256r1;
        static string ClientCertificate = "Cindy";
        static string ServerCertificate = "Derek";
        #endif

        static BigInteger ToBigIntegerFromHex(string text)
        {
            if (text == null || text.Length == 0)
            {
                return new BigInteger();
            }

            return BigInteger.Parse(text, System.Globalization.NumberStyles.HexNumber | System.Globalization.NumberStyles.AllowHexSpecifier);

            /*
            byte[] bytes = new byte[text.Length / 2];

            for (int ii = text.Length - 2; ii >= 0; ii -= 2)
            {
                bytes[(text.Length - 1 - ii)/2] = Convert.ToByte(text.Substring(ii, 2), 16); 
            }

            return new BigInteger(bytes);
            */
        }

        static BigInteger ToBigIntegerFromDecimal(string text)
        {
            if (text == null || text.Length == 0)
            {
                return new BigInteger();
            }

            var value = new BigInteger();

            for (int ii = 0; ii < text.Length; ii++)
            {
                value *= 10;
                value += Convert.ToByte(text[ii]);
            }

            return value;
        }

        static BigInteger ToBigIntegerFromNumber(byte[] number, int offset = 0, int length = -1)
        {
            if (number == null || number.Length == 0)
            {
                return new BigInteger();
            }

            if (length == -1)
            {
                length = number.Length;
            }

            StringBuilder text = new StringBuilder();

            for (int ii = 0; ii < length; ii++)
            {
                text.AppendFormat("{0:X2}", number[offset + ii]);
            }

            return BigInteger.Parse(text.ToString(), System.Globalization.NumberStyles.HexNumber | System.Globalization.NumberStyles.AllowHexSpecifier);
        }

        private static ECDsa GetManualECDsaPublicKey(X509Certificate2 cert)
        {
            if (cert.GetKeyAlgorithm() != "1.2.840.10045.2.1")
            {
                return null;
            }

            const X509KeyUsageFlags SufficientFlags =
                X509KeyUsageFlags.KeyAgreement |
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.NonRepudiation |
                X509KeyUsageFlags.CrlSign |
                X509KeyUsageFlags.KeyCertSign;

            foreach (X509Extension extension in cert.Extensions)
            {
                if (extension.Oid.Value == "2.5.29.15")
                {
                    X509KeyUsageExtension kuExt = (X509KeyUsageExtension)extension;

                    if ((kuExt.KeyUsages & SufficientFlags) == 0)
                    {
                        return null;
                    }
                }
            }

            PublicKey encodedPublicKey = cert.PublicKey;
            string keyParameters = BitConverter.ToString(encodedPublicKey.EncodedParameters.RawData);
            byte[] keyValue = encodedPublicKey.EncodedKeyValue.RawData;

            ECParameters ecParameters = default(ECParameters);

            if (keyValue[0] != 0x04)
            {
                throw new InvalidOperationException("Only uncompressed points are supported");
            }

            byte[] x = new byte[(keyValue.Length - 1) / 2];
            byte[] y = new byte[x.Length];

            Buffer.BlockCopy(keyValue, 1, x, 0, x.Length);
            Buffer.BlockCopy(keyValue, 1 + x.Length, y, 0, y.Length);

            ecParameters.Q.X = x;
            ecParameters.Q.Y = y;

            // New values can be determined by running the dotted-decimal OID value
            // through BitConverter.ToString(CryptoConfig.EncodeOID(dottedDecimal));

            switch (keyParameters)
            {
                case "06-08-2A-86-48-CE-3D-03-01-07":
                    ecParameters.Curve = ECCurve.NamedCurves.nistP256;
                    break;
                case "06-09-2B-24-03-03-02-08-01-01-07":
                    ecParameters.Curve = ECCurve.NamedCurves.brainpoolP256r1;
                    break;
                default:
                    throw new NotImplementedException(keyParameters);
            }

            return ECDsa.Create(ecParameters);
        }

        static void CalculateY_NistP256()
        {
            try
            {
                var key = ECDiffieHellmanCng.Create(ECCurve.NamedCurves.nistP256);

                BigInteger a = ToBigIntegerFromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
                BigInteger m = ToBigIntegerFromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
                BigInteger b = ToBigIntegerFromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

                var xy = key.PublicKey.ToByteArray();
                BigInteger x = ToBigIntegerFromNumber(xy, 8, 32);
                BigInteger y1 = ToBigIntegerFromNumber(xy, 40, 32);

                // y2 = (pow(x, 3, m) + a * x + b) % m
                var r1 = BigInteger.ModPow(x, 3, m);
                var r2 = BigInteger.Multiply(a, x);
                var r3 = r1 + r2 + b;
                var r4 = r3 % m;

                // y = pow(y2, (m + 1) / 4, m)
                var r5 = BigInteger.Divide(m + 1, 4);
                var y2 = BigInteger.ModPow(r4, r5, m);

                if (!AreEqual(y1.ToByteArray(), y2.ToByteArray()))
                {
                    Console.WriteLine("CalculateY Failed");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("CalculateY Failed. " + e.Message);
            }
        }

        static void Main(string[] args)
        {
            EccOpenSsl.EccTester tester = new EccOpenSsl.EccTester();
            tester.Initialize();

            CalculateY_NistP256();

            // certs are generated with openssl and use the NIST p256 curve.
            string senderCertificateFilePath = Path.Combine("..\\..\\..\\..\\pki\\certs\\", ClientCertificate + ".der");
            string senderKeyFilePath = Path.Combine("..\\..\\..\\..\\pki\\private\\", ClientCertificate + ".pem");

            string receiverCertificateFilePath = Path.Combine("..\\..\\..\\..\\pki\\certs\\", ServerCertificate + ".der");
            string receiverKeyFilePath = Path.Combine("..\\..\\..\\..\\pki\\private\\", ServerCertificate + ".pem");

            // set the certificate used by the openssl side.
            tester.SetLocalCertificate(receiverCertificateFilePath, receiverKeyFilePath, null);

            senderKeyFilePath = Path.Combine("..\\..\\..\\..\\pki\\private\\", ClientCertificate + ".pfx");
            X509Certificate2 sender = new X509Certificate2(senderKeyFilePath, "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);

            // create a 'open secure channel request' that includes an ephermal key generated in .NET.
            ECDiffieHellmanCng clientEmpheralKey;
            byte[] clientNonce = null;
            CreateOpenSecureChannelRequest(sender, "request.uabinary", out clientEmpheralKey, out clientNonce);
            Debug.Assert(clientEmpheralKey != null);

            // validates the signature created in .NET and creates reply that includes an ephermal key generated by OpenSSL.
            // The shared key is created by OpenSSL (private) * .NET (public).
            byte[] clientSecret1 = null;
            byte[] serverSecret1 = null;
            tester.Decode("request.uabinary", "response.uabinary", ref clientSecret1, ref serverSecret1);

            // validates the signature created in OpenSSL.
            // The shared key is created by .NET (private) * .OpenSSL (public).
            // sharedKey1 and sharedKey2 are supposed to be the same - they aren't.
            byte[] serverNonce = null;
            ECDiffieHellman serverEmpheralKey = ProcessOpenSecureChannelResponse(sender, clientEmpheralKey, "response.uabinary", out serverNonce);

            clientEmpheralKey.Seed = null;
            clientEmpheralKey.SecretAppend = null;
            clientEmpheralKey.SecretPrepend = null;

            var nonce = new UTF8Encoding().GetBytes("client");
            Console.WriteLine("NET: ClientNonce: {0}", FormatHexString(nonce));
            var clientSecret2 = clientEmpheralKey.DeriveKeyFromHmac(serverEmpheralKey.PublicKey, HashAlgorithmName.SHA256, null, nonce, null);
            Console.WriteLine("NET: ClientSecret: {0}", FormatHexString(clientSecret2));

            if (!AreEqual(clientSecret1, clientSecret2))
            {
                Console.WriteLine("CLIENT KEYS DO NOT MATCH!");
            }

            nonce = new UTF8Encoding().GetBytes("server");
            Console.WriteLine("NET: ServerNonce: {0}", FormatHexString(nonce));

            var serverSecret2 = clientEmpheralKey.DeriveKeyFromHmac(serverEmpheralKey.PublicKey, HashAlgorithmName.SHA256, null, nonce, null);
            Console.WriteLine("NET: ServerSecret: {0}", FormatHexString(serverSecret2));

            if (!AreEqual(serverSecret1, serverSecret2))
            {
                Console.WriteLine("SERVER KEYS DO NOT MATCH!");
            }

            Console.WriteLine("==== NET Derived Keys ====");
            var serverKeys = DeriveKeys(serverSecret2, clientSecret2, 80);
            Console.WriteLine("NET: ServerSigningKey: {0}", FormatHexString(serverKeys, 0, 32));
            Console.WriteLine("NET: ServerEncryptingKey: {0}", FormatHexString(serverKeys, 32, 32));
            Console.WriteLine("NET: ServerInitializationVector: {0}", FormatHexString(serverKeys, 64, 16));

            var clientKeys = DeriveKeys(clientSecret2, serverSecret2, 80);
            Console.WriteLine("NET: ClientSigningKey: {0}", FormatHexString(clientKeys, 0, 32));
            Console.WriteLine("NET: ClientEncryptingKey: {0}", FormatHexString(clientKeys, 32, 32));
            Console.WriteLine("NET: ClientInitializationVector: {0}", FormatHexString(clientKeys, 64, 16));

            tester.Cleanup();
            Console.ReadLine();
        }

        static byte[] DeriveKeys(byte[] secret, byte[] seed, int length)
        {
            //Console.WriteLine("NET: Secret: {0}", FormatHexString(secret));
            //Console.WriteLine("NET: Seed: {0}", FormatHexString(seed));

            HMACSHA256 hmac = new HMACSHA256(secret);

            byte[] keySeed = hmac.ComputeHash(seed);
            //Console.WriteLine("NET: A(1): {0}", FormatHexString(keySeed));

            byte[] prfSeed = new byte[hmac.HashSize/8 + seed.Length];
            Buffer.BlockCopy(keySeed, 0, prfSeed, 0, keySeed.Length);
            Buffer.BlockCopy(seed, 0, prfSeed, keySeed.Length, seed.Length);
            //Console.WriteLine("NET: S(1): {0}", FormatHexString(prfSeed));

            // create buffer with requested size.
            byte[] output = new byte[length];

            int position = 0;

            do
            {
                byte[] hash = hmac.ComputeHash(prfSeed);
                //Console.WriteLine("NET: R(1): {0}", FormatHexString(hash));

                for (int ii = 0; position < length && ii < hash.Length; ii++)
                {
                    output[position++] = hash[ii];
                }

                keySeed = hmac.ComputeHash(keySeed);
                Buffer.BlockCopy(keySeed, 0, prfSeed, 0, keySeed.Length);
            }
            while (position < length);

            return output;
        }

        static bool AreEqual(IList<byte> value1, IList<byte> value2)
        {
            if (value1 == null || value2 == null || value2.Count != value1.Count)
            {
                return false;
            }

            for (int ii = 0; ii < value1.Count; ii++)
            {
                if (value1[ii] != value2[ii])
                {
                    return false;
                }
            }

            return true;
        }

        static byte[] Encode(X509Certificate2 publicKey, ECDsaCng signingKey, ECDiffieHellmanCng ephemeralKey, byte[] senderNonce)
        {
            var data = ephemeralKey.Key.Export(CngKeyBlobFormat.EccPublicBlob);
            var signingCertificate = publicKey.RawData;

            var buffer = new byte[UInt16.MaxValue];

            int ephemeralKeySize = ephemeralKey.KeySize / 4;

            int length = 16 + ephemeralKeySize + signingCertificate.Length + senderNonce.Length;

            int signatureLength = signingKey.KeySize / 4;
            length += signatureLength;

            using (var ostrm = new System.IO.MemoryStream(buffer, true))
            {
                ostrm.Write(BitConverter.GetBytes(length), 0, 4);
                ostrm.Write(BitConverter.GetBytes(signingCertificate.Length), 0, 4);
                ostrm.Write(signingCertificate, 0, signingCertificate.Length);
                ostrm.Write(BitConverter.GetBytes(ephemeralKeySize), 0, 4);
                ostrm.Write(data, 8, ephemeralKeySize);
                ostrm.Write(BitConverter.GetBytes(senderNonce.Length), 0, 4);
                ostrm.Write(senderNonce, 0, senderNonce.Length);

                SHA256Cng sha = new SHA256Cng();
                var hash = sha.ComputeHash(buffer, 0, length - signatureLength);
                // Console.WriteLine("HASH {0}", FormatHexString(hash));

                var signature = signingKey.SignData(buffer, 0, length - signatureLength, HashAlgorithmName.SHA256);
                // Console.WriteLine("SIG {0}", FormatHexString(signature));
                ostrm.Write(signature, 0, signature.Length);
                ostrm.Close();

                using (ECDsa ecdsa = GetManualECDsaPublicKey(publicKey))
                {
                    if (!ecdsa.VerifyData(buffer, 0, length - signature.Length, signature, HashAlgorithmName.SHA256))
                    {
                        throw new Exception("Generated signature not valid.");
                    }
                }

                return ostrm.ToArray();
            }
        }

        static ECDiffieHellman Decode(ECCurve curve, byte[] data, out byte[] senderNonce)
        {
            var length = BitConverter.ToInt32(data, 0);

            var signingCertificateLength = BitConverter.ToInt32(data, 4);
            var signingCertificate = new byte[signingCertificateLength];
            Buffer.BlockCopy(data, 8, signingCertificate, 0, signingCertificateLength);

            var publicKey = new X509Certificate2(signingCertificate);
            ECParameters parameters;

            using (ECDsa ecdsa = GetManualECDsaPublicKey(publicKey))
            {
                var signature = new byte[ecdsa.KeySize / 4];
                Buffer.BlockCopy(data, length - signature.Length, signature, 0, signature.Length);

                SHA256Cng sha = new SHA256Cng();
                var hash = sha.ComputeHash(data, 0, length - signature.Length);
                // Console.WriteLine("HASH {0}", FormatHexString(hash));
                // Console.WriteLine("SIG {0}", FormatHexString(signature));

                if (!ecdsa.VerifyData(data, 0, length - signature.Length, signature, HashAlgorithmName.SHA256))
                {
                    throw new Exception("Received signature not valid.");
                }

                parameters = ecdsa.ExportParameters(false);
            }

            int start = 8 + signingCertificateLength;
            var keyLength = BitConverter.ToInt32(data, start);
            start += 4;

            int nonceLength = BitConverter.ToInt32(data, start + keyLength);
            senderNonce = new byte[nonceLength];
            Array.Copy(data, start + keyLength + 4, senderNonce, 0, senderNonce.Length);

            using (var ostrm = new System.IO.MemoryStream())
            {
                byte[] qx = new byte[keyLength/2];
                byte[] qy = new byte[keyLength / 2];
                Buffer.BlockCopy(data, start, qx, 0, keyLength / 2);
                Buffer.BlockCopy(data, start + keyLength / 2, qy, 0, keyLength / 2);

                var ecdhParameters = new ECParameters
                {
                    Curve = parameters.Curve,
                    Q = { X = qx, Y = qy }
                };

                return ECDiffieHellman.Create(ecdhParameters);
            }
        }

        static byte[] Encode(ECDiffieHellmanCng ephemeralKey)
        {
            var data = ephemeralKey.Key.Export(CngKeyBlobFormat.EccPublicBlob);

            int ephemeralKeySize = ephemeralKey.KeySize / 4;
            int length = 4 + ephemeralKeySize;

            byte[] buffer = new byte[length];
            Buffer.BlockCopy(BitConverter.GetBytes(ephemeralKeySize), 0, buffer, 0, 4);
            Buffer.BlockCopy(data, 8, buffer, 0, ephemeralKeySize);
            return buffer;
        }
        
        static string FormatHexString(byte[] bytes, int offset = 0, int length = -1)
        {
            if (length < 0)
            {
                length = bytes.Length;
            }

            System.Text.StringBuilder buffer = new StringBuilder();

            for (int ii = offset; ii < offset + length; ii++)
            {
                buffer.AppendFormat("{0:X2}", bytes[ii]);
            }

            return buffer.ToString();
        }

        static byte[] CreateOpenSecureChannelRequest(X509Certificate2 sender, string requestFilePath, out ECDiffieHellmanCng senderECDH, out byte[] senderNonce)
        {
            X509Certificate2 senderPublicKey = new X509Certificate2(sender.RawData);
            var senderPrivateKey = sender.GetECDsaPrivateKey() as ECDsaCng;

            var parameters = sender.GetECDsaPrivateKey().ExportParameters(false);
            senderECDH = (ECDiffieHellmanCng)ECDiffieHellmanCng.Create(parameters.Curve);
            senderECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hmac;
            senderECDH.HashAlgorithm = CngAlgorithm.Sha256;
            
            senderNonce = new byte[senderECDH.KeySize / 8];
            new RNGCryptoServiceProvider().GetBytes(senderNonce);
            senderECDH.Seed = senderNonce;

            var request = Encode(senderPublicKey, senderPrivateKey, senderECDH, senderNonce);
            System.IO.File.WriteAllBytes(requestFilePath, request);
            return request;
        }

        static byte[] ProcessOpenSecureChannelRequest(X509Certificate2 receiver, string requestFilePath, string responseFilePath, out byte[] receiverNonce)
        {
            var request = System.IO.File.ReadAllBytes(requestFilePath);

            var parameters = receiver.GetECDsaPublicKey().ExportParameters(false);
            byte[] senderNonce = null;
            var senderKeyData = Decode(parameters.Curve, request, out senderNonce);

            X509Certificate2 receiverPublicKey = new X509Certificate2(receiver.RawData);
            var receiverPrivateKey = receiver.GetECDsaPrivateKey() as ECDsaCng;

            ECDiffieHellmanCng receiverECDH = new ECDiffieHellmanCng(parameters.Curve);
            receiverECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hmac;
            receiverECDH.HashAlgorithm = CngAlgorithm.Sha256;

            receiverNonce = new byte[receiverECDH.KeySize / 2];
            new RNGCryptoServiceProvider().GetBytes(receiverNonce);
            receiverECDH.Seed = receiverNonce;

            byte[] receiverSecret = receiverECDH.DeriveKeyFromHmac(senderKeyData.PublicKey, HashAlgorithmName.SHA256, receiverNonce);

            var response = Encode(receiverPublicKey, receiverPrivateKey, receiverECDH, receiverNonce);
            System.IO.File.WriteAllBytes(responseFilePath, response);
            return response;
        }

        static ECDiffieHellman ProcessOpenSecureChannelResponse(X509Certificate2 receiver, ECDiffieHellmanCng senderECDH, string responseFilePath, out byte[] serverNonce)
        {
            var response = System.IO.File.ReadAllBytes(responseFilePath);;
            var parameters = receiver.GetECDsaPrivateKey().ExportParameters(false);
            return Decode(parameters.Curve, response, out serverNonce);
        }
    }
}
