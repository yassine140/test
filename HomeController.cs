using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Mvc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;
using System.Runtime.Serialization;
using Org.BouncyCastle.OpenSsl;

namespace MvcApplication1.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/
       public ActionResult Test()
        {
            var csp = new RSACryptoServiceProvider(2048);

            //how to get the private key
            //var privKey = csp.ExportParameters(true);
            var privKey = PrivateKeyFromPemFile();

            //and the public key ...
            //var pubKey = csp.ExportParameters(false);
            var pubKey = PublicKeyFromPemFile();

            //converting the public key into a string representation
            string pubKeyString;
            {
                //we need some buffer
                var sw = new System.IO.StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream

                xs.Serialize(sw, pubKey);
                //get the string from the stream
                pubKeyString = sw.ToString();
                ViewBag.publicKey = pubKeyString;
            }

            //converting it back
            {
                //get a stream from the string
                var sr = new System.IO.StringReader(pubKeyString);
                //we need a deserializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //get the object back from the stream
                pubKey = (RSAParameters)xs.Deserialize(sr);
            }

            //conversion for the private key is no black magic either ... omitted

            //we have a public key ... let's get a new csp and load that key
            
           
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(pubKey);

            using (AesManaged aes = new AesManaged())
            {
                String key = Convert.ToBase64String(aes.Key, 0, aes.Key.Length);
                String iv = Convert.ToBase64String(aes.IV, 0, aes.IV.Length);

                var aesKeyBytes = System.Convert.FromBase64String(key);
                var aesIvBytes = System.Convert.FromBase64String(iv);
                ViewBag.key = key;
                ViewBag.iv = iv;

                var plainTextData = "hello world";
                ViewBag.txt = plainTextData;
                var cyphertexte = Encrypt(plainTextData, aesKeyBytes, aesIvBytes); //texte crypter avec aes
                var aeskeyBytesCrypted = csp.Encrypt(aesKeyBytes, false);         //clé et iv crypter avec rsa
                var aesIvBytesCrypted  = csp.Encrypt(aesIvBytes, false);
                var x = Convert.ToBase64String(cyphertexte, 0, cyphertexte.Length) + "*"+ Convert.ToBase64String(aeskeyBytesCrypted, 0, aeskeyBytesCrypted.Length) + "*"+ Convert.ToBase64String(aesIvBytesCrypted, 0, aesIvBytesCrypted.Length);
                ViewBag.messagecrypter = x;




                csp = new RSACryptoServiceProvider();
                csp.ImportParameters(privKey);
                string[] tab = x.Split('*');
                var aeskey = System.Convert.FromBase64String(tab[1]);
                var aesiv = System.Convert.FromBase64String(tab[2]);

                var aeskeyBytesDecrypted = csp.Decrypt(aeskey,false);
                var aesIvBytesDecrypted = csp.Decrypt(aesiv, false);
                var plainText = Decrypt(cyphertexte, aeskeyBytesDecrypted, aesIvBytesDecrypted);

                var y = plainText +"*" + Convert.ToBase64String(aeskeyBytesDecrypted, 0, aeskeyBytesDecrypted.Length) +"*" + Convert.ToBase64String(aesIvBytesDecrypted, 0, aesIvBytesDecrypted.Length);
                ViewBag.messagedecrypter = y;

            }
            return View();
        }
        public static RSAParameters PrivateKeyFromPemFile() //(String filePath)
        {
            using (TextReader privateKeyTextReader = new StringReader(System.IO.File.ReadAllText("C:\\cygwin64\\home\\starinfo\\rsa1.private"))) //(filePath)))
            {
                AsymmetricCipherKeyPair readKeyPair = (AsymmetricCipherKeyPair)new PemReader(privateKeyTextReader).ReadObject();


                RsaPrivateCrtKeyParameters privateKeyParams = ((RsaPrivateCrtKeyParameters)readKeyPair.Private);
                //RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned();
                parms.P = privateKeyParams.P.ToByteArrayUnsigned();
                parms.Q = privateKeyParams.Q.ToByteArrayUnsigned();
                parms.DP = privateKeyParams.DP.ToByteArrayUnsigned();
                parms.DQ = privateKeyParams.DQ.ToByteArrayUnsigned();
                parms.InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned();
                parms.D = privateKeyParams.Exponent.ToByteArrayUnsigned();
                parms.Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned();

                //cryptoServiceProvider.ImportParameters(parms);

                return parms;
            }
        }

        public static RSAParameters PublicKeyFromPemFile() //(String filePath)
        {
            using (TextReader publicKeyTextReader = new StringReader(System.IO.File.ReadAllText("C:\\cygwin64\\home\\starinfo\\rsa1.public")))   //(filePath)))
            {
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)new PemReader(publicKeyTextReader).ReadObject();

                //RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();



                parms.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
                parms.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();


                //cryptoServiceProvider.ImportParameters(parms);

                //return cryptoServiceProvider;
                return parms;
            }
        }
    
        public ActionResult Index()
        {

            using (AesManaged aes = new AesManaged())
            {
                String key = Convert.ToBase64String(aes.Key, 0, aes.Key.Length);
                String iv = Convert.ToBase64String(aes.IV, 0, aes.IV.Length);

                var aesKeyBytes = System.Convert.FromBase64String(key);
                var aesIvBytes = System.Convert.FromBase64String(iv);
                byte[] encryptedBytes = Encrypt("hello word", aesKeyBytes, aesIvBytes);
                string encryptedMessage = Convert.ToBase64String(encryptedBytes, 0, encryptedBytes.Length);
                ViewBag.key = key;
                ViewBag.iv = iv;
                ViewBag.encrypted = encryptedMessage;
                string decryptedmessage = Decrypt(encryptedBytes, aesKeyBytes, aesIvBytes);
                ViewBag.decrypted = decryptedmessage;
            }
            return View();
        }
        public static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            // Create a new AesManaged.    
            using (AesManaged aes = new AesManaged())
            {
                // Create encryptor    
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
                // Create MemoryStream    
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption    
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                    // to encrypt    
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream    
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data    
            return encrypted;
        }
        public static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            // Create AesManaged    
            using (AesManaged aes = new AesManaged())
            {
                // Create a decryptor    
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.    
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream    
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream    
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }   
   
    
    
    
    
    }
}
