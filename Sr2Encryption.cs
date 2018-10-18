using System;
using System.Collections.Generic;
using System.Net;
using System.IO;
using System.Text;
using Newtonsoft.Json;

namespace Sr2Solutions
{
    public class Sr2Encryption
    {
        public class Sr2KeyData
        {
            private byte[] _plainText;
            private string _cipherText;

            internal Sr2KeyData(string plainText, string cipherText)
            {
                this._plainText = Convert.FromBase64String(plainText);
                this._cipherText = cipherText;
            }

            public byte[] Plaintext
            {
                get
                {
                    return this._plainText;
                }
            }

            public string CipherText
            {
                get
                {
                    return this._cipherText;
                }
            }
        }

        public class Sr2EncryptionKey
        {
            private string _keyId;
            private DateTime _createdAt;
            private bool _active;
            private bool _additionalAuth;

            internal Sr2EncryptionKey(string KeyId, string CreatedAt, string Active, string AdditionalAuth)
            {
                this._keyId = KeyId;
                this._createdAt = DateTime.Parse(CreatedAt);
                this._active = bool.Parse(Active);
                this._additionalAuth = AdditionalAuth == "notset" ? false : true;
            }

            public string KeyId
            {
                get
                {
                    return this._keyId;
                }
            }

            public DateTime CreatedAt
            {
                get
                {
                    return this._createdAt;
                }
            }

            public bool Active
            {
                get
                {
                    return this._active;
                }
            }

            public bool AdditionalAuthSet
            {
                get
                {
                    return this._additionalAuth;
                }
            }
        }

        private string _scheme = "https://";
        private string _host;
        private string _licenseId;
        private string _licenseSeceret;

        /// <summary>
        /// Initialize an Sr2Encryption object with your Host, LicenseId, and LicenseSecret which was sent to you when you signed up for the SR2 Encryption Service.
        /// </summary>
        /// <param name="host">use demo.sr2encryption.com for a free demonstration.</param>
        /// <param name="licenseId">The License ID that was provided when you registered. Use 15f264a7-c844-4324-b58b-57df2e945c8e for a free demonstration.</param>
        /// <param name="licenseSecret">The License Secret that was provided when you registered. Keep this in a secure location. Use the following key for a free demonstration. Ne+XlrLXAxx2kALp6dnEE3tKllC0VKB8VGApOdiGhW3j1cwrfQ6/lktVCsBVCbnJCGTJmB8fDtooF5dpbV/xMQ==</param>
        public Sr2Encryption(string host, string licenseId, string licenseSecret)
        {
            this._host = host;
            this._licenseId = licenseId;
            this._licenseSeceret = licenseSecret;
        }

        /// <summary>
        /// Initialize an Sr2Encryption object with the built in free demonstration values.
        /// </summary>
        public Sr2Encryption()
        {
            this._host = "demo.sr2encryption.com";
            this._licenseId = "15f264a7-c844-4324-b58b-57df2e945c8e";
            this._licenseSeceret = "Ne+XlrLXAxx2kALp6dnEE3tKllC0VKB8VGApOdiGhW3j1cwrfQ6/lktVCsBVCbnJCGTJmB8fDtooF5dpbV/xMQ==";
        }

        private static Dictionary<string, object> simpleAuthenticatedPost(string scheme, string host, string path, Dictionary<string, string> headers, Dictionary<string, object> requestBody)
        {
            HttpWebRequest http = (HttpWebRequest)WebRequest.Create(new Uri(string.Format("{0}{1}{2}", scheme, host, path)));
            http.Accept = "applicaiton/json";
            http.ContentType = "application/json";
            http.Method = "POST";

            foreach (string keyName in headers.Keys)
            {
                http.Headers[keyName] = headers[keyName];
            }

            string bodyString = JsonConvert.SerializeObject(requestBody);
            byte[] payload = Encoding.UTF8.GetBytes(bodyString);

            Stream outboundStream = http.GetRequestStream();
            outboundStream.Write(payload, 0, payload.Length);
            outboundStream.Close();

            HttpWebResponse response = (HttpWebResponse)http.GetResponse();

            Stream inboundStream = response.GetResponseStream();
            StreamReader sr = new StreamReader(inboundStream);

            string resultString = sr.ReadToEnd();

            return JsonConvert.DeserializeObject<Dictionary<string, object>>(resultString);
        }

        /// <summary>
        /// Before you can start encrypting data you must create an encryption key within your account. You have the option of adding some additional authentication data in Base64 format to the key that will be created. But it will be needed for all future operations with the key that is created.
        ///
        /// The key material is stored on the SR2 Encryption Server securely and cannot be accessed by our team.They are encrypted using the License Secret that you were provided at the start of your service.
        /// </summary>
        /// <returns>A string containing the Key ID that can be used to encrypt data.</returns>
        public string createKey()
        {
            return this.createKey(null);
        }

        /// <summary>
        /// Before you can start encrypting data you must create an encryption key within your account. You have the option of adding some additional authentication data in Base64 format to the key that will be created. But it will be needed for all future operations with the key that is created.
        ///
        /// The key material is stored on the SR2 Encryption Server securely and cannot be accessed by our team.They are encrypted using the License Secret that you were provided at the start of your service.
        /// </summary>
        /// <param name="additionalAuth">Additional authentication data that will be required whenever using this Encryption Key.</param>
        /// <returns>A string containing the Key ID that can be used to encrypt data.</returns>
        public string createKey(byte[] additionalAuth)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            Dictionary<string, object> body = new Dictionary<string, object>();

            if (additionalAuth != null)
            {
                body["AdditionalAuth"] = Convert.ToBase64String(additionalAuth);
            }

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/createkey", headers, body);

            if ((string)result["status"] == "success")
            {
                return (string)result["KeyId"];
            }
            else
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Get a list of all encryption keys on your SR2 Encryption server. This will not return raw key data. Instead it returns Key IDs, the creation date of the key, and the current status of the key.
        /// </summary>
        /// <returns>A list of your encryption keys.</returns>
        public List<Sr2EncryptionKey> listKeys()
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            Dictionary<string, object> body = new Dictionary<string, object>();

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/listkeys", headers, body);

            if ((string)result["status"] == "success")
            {
                List<Sr2EncryptionKey> retval = new List<Sr2EncryptionKey>();

                foreach (Newtonsoft.Json.Linq.JObject obj in (Newtonsoft.Json.Linq.JArray)result["Keys"])
                {
                    retval.Add(new Sr2EncryptionKey(obj["KeyId"].ToString(), obj["CreatedAt"].ToString(), obj["Active"].ToString(), obj["AdditionalAuth"].ToString()));
                }

                return retval;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// This is useful if you want to prevent encryption using a key in the future but still be able to decrypt data with that key.
        /// </summary>
        /// <param name="KeyId">The Key ID of the key that you want to deactivate.</param>
        /// <returns>True if successful, otherwise false.</returns>
        public bool deactivateKey(string KeyId)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["KeyId"] = KeyId;

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/deactivatekey", headers, body);

            if ((string)result["status"] == "success")
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// This is useful if you want to prevent encryption AND decryption using a key in the future. Once a key has been deleted you will not be able to decrypt any data that is secured with that key.
        /// </summary>
        /// <param name="KeyId">The Key ID of the key that you want to delete.</param>
        /// <returns>True if successful, otherwise false.</returns>
        public bool deleteKey(string KeyId)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["KeyId"] = KeyId;

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/deletekey", headers, body);

            if ((string)result["status"] == "success")
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Now that you have an encryption Key ID you can start encrypting data. If successful, the cipherTextString contains the encrypted data, a properly formatted initialization vector, and the Key ID that was used all in a single Base64 formatted string. The SR2 Encryption service limits you to 64KB of data to be encrypted.
        /// </summary>
        /// <param name="KeyId">The Key ID that you want to use for encryption which was created using createKey().</param>
        /// <param name="PlaintextData">The data that you want to encrypt.</param>
        /// <returns>A Base64 string of the encrypted data which also contains the KeyId and Initialization Vector (IV) that was used.</returns>
        public string encryptData(string KeyId, byte[] PlaintextData)
        {
            return this.encryptData(KeyId, PlaintextData, null);
        }

        /// <summary>
        /// Now that you have an encryption Key ID you can start encrypting data. If successful, the cipherTextString contains the encrypted data, a properly formatted initialization vector, and the Key ID that was used all in a single Base64 formatted string. The SR2 Encryption service limits you to 64KB of data to be encrypted.
        /// </summary>
        /// <param name="KeyId">The Key ID that you want to use for encryption which was created using createKey().</param>
        /// <param name="PlaintextData">The data that you want to encrypt.</param>
        /// <param name="AdditionalAuth">Additional authentication data that was used during the createKey() process.</param>
        /// <returns>A Base64 string of the encrypted data which also contains the KeyId and Initialization Vector (IV) that was used.</returns>
        public string encryptData(string KeyId, byte[] PlaintextData, byte[] AdditionalAuth)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            if (AdditionalAuth != null)
            {
                headers["x-additionalauth"] = Convert.ToBase64String(AdditionalAuth);
            }

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["KeyId"] = KeyId;
            body["Plaintext"] = Convert.ToBase64String(PlaintextData);

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/encrypt", headers, body);

            if ((string)result["status"] == "success")
            {
                return (string)result["CipherText"];
            }
            else
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Be sure to pass in the same Base64 string that you were given in the encrypt function. The PlaintextBuffer that given to you after the function completes is a full Buffer object that matches whatever data you encrypted.
        /// </summary>
        /// <param name="CipherText">The Base64 string of data that was encrypted on the SR2 Encryption server.</param>
        /// <returns>The unencrypted data if decryption was successful. Otherwise null.</returns>
        public byte[] decryptData(string CipherText)
        {
            return this.decryptData(CipherText, null);
        }

        /// <summary>
        /// Be sure to pass in the same Base64 string that you were given in the encrypt function. The PlaintextBuffer that given to you after the function completes is a full Buffer object that matches whatever data you encrypted.
        /// </summary>
        /// <param name="CipherText">The Base64 string of data that was encrypted on the SR2 Encryption server.</param>
        /// <param name="AdditionalAuth">Additional authentication data that was used during the createKey() process.</param>
        /// <returns>The unencrypted data if decryption was successful. Otherwise null.</returns>
        public byte[] decryptData(string CipherText, byte[] AdditionalAuth)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            if (AdditionalAuth != null)
            {
                headers["x-additionalauth"] = Convert.ToBase64String(AdditionalAuth);
            }

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["CipherText"] = CipherText;

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/decrypt", headers, body);

            if ((string)result["status"] == "success")
            {
                return Convert.FromBase64String((string)result["Plaintext"]);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Depending on your security policies, you may have to rotate encryption keys from time to time. After creating a second key, you can reencrypt some data using the ReEncryptData function. This will safely decrypt encrypted text using the old key and then encrypt it with the new key that you specify. This never exposes the contents of your data.
        /// </summary>
        /// <param name="CipherText">The Base64 string of data that was encrypted on the SR2 Encryption server.</param>
        /// <param name="DestinationKeyId">The Key ID that you want to reencrypt that data with</param>
        /// <param name="DestinationAdditionalAuth">Additional authentication data that was used during the createKey() process.</param>
        /// <param name="SourceAdditionalAuth">Additional authentication data that was used during the createKey() process.</param>
        /// <returns>A Base64 string of the encrypted data which also contains the KeyId and Initialization Vector (IV) that was used.</returns>
        public string reEncryptData(string CipherText, string DestinationKeyId, byte[] DestinationAdditionalAuth, byte[] SourceAdditionalAuth)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            if (SourceAdditionalAuth != null)
            {
                headers["x-additionalauth"] = Convert.ToBase64String(SourceAdditionalAuth);
            }

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["CipherText"] = CipherText;
            body["DestinationKeyId"] = DestinationKeyId;

            if (DestinationAdditionalAuth != null)
            {
                body["DestinationAdditionalAuth"] = Convert.ToBase64String(DestinationAdditionalAuth);
            }

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/reencrypt", headers, body);

            if ((string)result["status"] == "success")
            {
                return (string)result["CipherText"];
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// It is always recommended to use an Initialization Vector (IV) when encrypting data. This helps prevent potential bad actors from spotting patterns in encrypted data that could be used to figure out your encryption key. To do this you should use a cryptographically secure random number generator. We provide that functionality with the generateRandomData() function.
        /// </summary>
        /// <param name="DataLength">The length in bytes of the random data that you need. This is limited to 64KB.</param>
        /// <returns>Randomly generated data with a length equal to DataLength.</returns>
        public byte[] generateRandomData(int DataLength)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["DataLength"] = DataLength;

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/generateRandomData", headers, body);

            if ((string)result["status"] == "success")
            {
                return Convert.FromBase64String((string)result["RandomData"]);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// It doesn't make sense to encrypt large amounts of data using the SR2 Encryption Service. From a performance standpoint you are much better off encrypting that data on your own servers. But creating cryptographically secure keys for that process can be problematic. So we have implemented functions for a process known as Envelope Encryption. Basically we will generate a cryptographically secure encryption key that you can use with AES 256bit on your own system, and encrypt it using a key that was generated using createKey() making it safe to store within your infrastructure.
        /// </summary>
        /// <param name="KeyId">The Key ID to use for encrypted the generated key.</param>
        /// <returns>An Sr2KeyData object containing both a Plaintext and CipherText version of the generated key</returns>
        public Sr2KeyData generateKeyData(string KeyId)
        {
            return this.generateKeyData(KeyId, null);
        }

        /// <summary>
        /// It doesn't make sense to encrypt large amounts of data using the SR2 Encryption Service. From a performance standpoint you are much better off encrypting that data on your own servers. But creating cryptographically secure keys for that process can be problematic. So we have implemented functions for a process known as Envelope Encryption. Basically we will generate a cryptographically secure encryption key that you can use with AES 256bit on your own system, and encrypt it using a key that was generated using createKey() making it safe to store within your infrastructure.
        /// </summary>
        /// <param name="KeyId">The Key ID to use for encrypted the generated key.</param>
        /// <param name="AdditionalAuth">Additional authentication data that was used during the createKey() process.</param>
        /// <returns>An Sr2KeyData object containing both a Plaintext and CipherText version of the generated key</returns>
        public Sr2KeyData generateKeyData(string KeyId, byte[] AdditionalAuth)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            if (AdditionalAuth != null)
            {
                headers["x-additionalauth"] = Convert.ToBase64String(AdditionalAuth);
            }

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["KeyId"] = KeyId;

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/generateKeyData", headers, body);

            if ((string)result["status"] == "success")
            {
                return new Sr2KeyData((string)result["Plaintext"], (string)result["CipherText"]);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Additionally, you can request just the encrypted copy of the key for storage only. This is useful if you don't need to use the key right away.
        /// </summary>
        /// <param name="KeyId">The Key ID to use for encrypted the generated key.</param>
        /// <returns>A Base64 string containing an encrypted version of the generated key which can be decrypted using decryptData().</returns>
        public string generateKeyDataWithoutPlaintext(string KeyId)
        {
            return this.generateKeyDataWithoutPlaintext(KeyId, null);
        }

        /// <summary>
        /// Additionally, you can request just the encrypted copy of the key for storage only. This is useful if you don't need to use the key right away.
        /// </summary>
        /// <param name="KeyId">The Key ID to use for encrypted the generated key.</param>
        /// <param name="AdditionalAuth">Additional authentication data that was used during the createKey() process.</param>
        /// <returns>A Base64 string containing an encrypted version of the generated key which can be decrypted using decryptData().</returns>
        public string generateKeyDataWithoutPlaintext(string KeyId, byte[] AdditionalAuth)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            if (AdditionalAuth != null)
            {
                headers["x-additionalauth"] = Convert.ToBase64String(AdditionalAuth);
            }

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["KeyId"] = KeyId;

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/aes/generateKeyDataWithoutPlaintext", headers, body);

            if ((string)result["status"] == "success")
            {
                return (string)result["CipherText"];
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Data of all types can be digitally signed by your SR2 Encryption Server. This is done using a unique RSA 4096bit key pair. This can be useful for making sure that data has not been tampered with. You can only sign 64KB of data at a time. We go into how to sign larger amounts of data like files further down.
        /// </summary>
        /// <param name="PlaintextData">The data that you want to sign. This is limited to 64KB in size.</param>
        /// <returns>A Base64 string containing the digital signature.</returns>
        public string signThisData(byte[] PlaintextData)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["x-licenseid"] = this._licenseId;
            headers["x-licensesecret"] = this._licenseSeceret;

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["Plaintext"] = Convert.ToBase64String(PlaintextData);

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/dsa/sign", headers, body);

            if ((string)result["status"] == "success")
            {
                return (string)result["Signature"];
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Verify data that was signed with signThisData()
        /// </summary>
        /// <param name="PlaintextData">The data that you want to verify with the signature. This is limited to 64KB in size.</param>
        /// <param name="SignatureString">A signature string that was generated using signThisData().</param>
        /// <returns></returns>
        public bool verifyThisSignatureOfThisData(byte[] PlaintextData, string SignatureString)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();

            Dictionary<string, object> body = new Dictionary<string, object>();
            body["Plaintext"] = Convert.ToBase64String(PlaintextData);
            body["Signature"] = SignatureString;

            Dictionary<string, object> result = simpleAuthenticatedPost(this._scheme, this._host, "/dsa/verify", headers, body);

            if ((string)result["status"] == "success")
            {
                return (bool)result["Verified"];
            }
            else
            {
                return false;
            }
        }

    }
}
