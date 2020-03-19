using PemUtils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace MvcApplication2.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            ViewBag.message_crypter = encrypt("hello world", "C:\\cygwin64\\home\\starinfo\\rsa1.public");
            string txtcry = encrypt("hello world", "C:\\cygwin64\\home\\starinfo\\rsa1.public");
            ViewBag.message_decrypter = decrypt(txtcry, "C:\\cygwin64\\home\\starinfo\\rsa1.private");
            return View();
        }
        public static string encrypt(string elementToEncrypt, string pathPrivateKey)
        {
            string pem = System.IO.File.ReadAllText(pathPrivateKey);
            byte[] Buffer = getBytesFromPEMFile(pem, "PUBLIC KEY");
            System.Security.Cryptography.RSACryptoServiceProvider rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
            System.Security.Cryptography.RSAParameters rsaParam = rsa.ExportParameters(false);
            rsaParam.Modulus = Buffer;
            rsa.ImportParameters(rsaParam);
            byte[] text = Encoding.UTF8.GetBytes(elementToEncrypt); // Convert.FromBase64String(elementToEncrypt);
            byte[] encryptedMessageByte = rsa.Encrypt(text, false);
            return Convert.ToBase64String(encryptedMessageByte);
        }
      
        public static string decrypt(string elementToDesencrypt, string pathPublicKey)
        {
            string pem = System.IO.File.ReadAllText(pathPublicKey);
            byte[] Buffer = getBytesFromPEMFile(pem, "RSA PRIVATE KEY");
            System.Security.Cryptography.RSACryptoServiceProvider rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
            System.Security.Cryptography.RSAParameters rsaParam = rsa.ExportParameters(false);
            rsaParam.Modulus = Buffer;
            rsa.ImportParameters(rsaParam);
            byte[] text = Encoding.UTF8.GetBytes(elementToDesencrypt); //Convert.FromBase64String(elementToDesencrypt)
            byte[] encryptedMessageByte = rsa.Decrypt(text, false);
            return Convert.ToBase64String(encryptedMessageByte);
        }

        public static byte[] getBytesFromPEMFile(string pemString, string headerPEM)
        {
            string header = String.Format("-----BEGIN {0}-----", headerPEM);
            string footer = String.Format("-----END {0}-----", headerPEM);
            int start = pemString.IndexOf(header, StringComparison.Ordinal) + header.Length;
            int end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;
            if (start < 0 || end < 0)
            {
                return null;
            }
            return Convert.FromBase64String(pemString.Substring(start, end));
        }
        public static void Main()
        {
            //encrypt("hello world", "C:\cygwin64\home\starinfo\rsa1.public");    
            Console.WriteLine(encrypt("hi!", "C:\\cygwin64\\home\\starinfo\\rsa1.public"));
            string txtcry = encrypt("hi", "C:\\cygwin64\\home\\starinfo\\rsa1.public");
            Console.WriteLine(decrypt(txtcry, "C:\\cygwin64\\home\\starinfo\\rsa1.private"));
            Console.ReadLine();
        }

    }
}
