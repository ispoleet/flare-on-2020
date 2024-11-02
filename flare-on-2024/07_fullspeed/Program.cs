namespace fullspeed_sigs
{
    using System.Net;
    using System.Text;
    using System.Security.Cryptography;
    using System.IO.Compression;
    using System.Text.RegularExpressions;
    using System.Xml.Linq;
    using System.Text.Json;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Utilities.Encoders;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Agreement;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Engines;
    using System.Net.Sockets;
    using System.Threading.Tasks;
    using System;
    using System.Collections.Concurrent;
    using System.Threading;
   


    class Program
    {
        static readonly HttpClient client = new HttpClient();
        private const int Port = 12345; // The port number to listen on
        private static ConcurrentDictionary<int, string> _concurrentDictionary = new ConcurrentDictionary<int, string>();

        static async Task Main()
        {
            // String manipulation
            string exampleString = "Hello World";
            string lowerString = exampleString.ToLower();
            string upperString = exampleString.ToUpper();
            string trimmedString = exampleString.Trim();
            bool containsHello = exampleString.Contains("Hello");
            string replacedString = exampleString.Replace("World", "Universe");

            // File operations
            string filePath = @"temp.txt";
            File.WriteAllText(filePath, exampleString);
            string readFile = File.ReadAllText(filePath);

            // Networking
            WebClient client = new WebClient();
            byte[] data = client.DownloadData("http://example.com");

            // Encoding
            string encodedString = Convert.ToBase64String(Encoding.UTF8.GetBytes(exampleString));
            byte[] decodedBytes = Convert.FromBase64String(encodedString);
            string decodedString = Encoding.UTF8.GetString(decodedBytes);

            // LINQ and Collections
            List<int> numbers = new List<int> { 1, 2, 3, 4, 5 };
            int maxNumber = numbers.Max();
            int minNumber = numbers.Min();
            IEnumerable<int> sortedNumbers = numbers.OrderBy(n => n);

            // Math operations
            double squareRoot = Math.Sqrt(25);
            double power = Math.Pow(2, 3);
            double absoluteValue = Math.Abs(-10.5);

            // Additional Networking Functions
            string url = "http://example.com";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream responseStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(responseStream);
            string responseText = reader.ReadToEnd();

            // Cryptographic Functions
            // Simple MD5 hash
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes("Hello World");
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }

            // RSA Encryption and Decryption
            string original = "Hello World!";
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(original), true);
                byte[] decryptedData = rsa.Decrypt(encryptedData, true);
            }

            // Output network response and cryptographic results
            Console.WriteLine($"HTTP Response: {responseText}");

            // XML Parsing
            string xmlString = "<root><element>Value</element></root>";
            XDocument doc = XDocument.Parse(xmlString);
            string elementValue = doc.Root.Element("element").Value;

            // Json parsing
            string jsonString = "{\"name\":\"John Doe\",\"age\":30}";
            using (JsonDocument json_doc = JsonDocument.Parse(jsonString))
            {
                JsonElement root = json_doc.RootElement;
                string name = root.GetProperty("name").GetString();
                int age = root.GetProperty("age").GetInt32();
                Console.WriteLine($"Name: {name}, Age: {age}");
            }

            // Regular Expressions
            string data2 = "Example 123";
            Match match = Regex.Match(data2, @"\d+");
            string matchedNumber = match.Value;

            // File Compression
            string startPath = "./";
            string zipPath = "output.zip";
            ZipFile.CreateFromDirectory(startPath, zipPath);

            // Environment Information
            string osVersion = Environment.OSVersion.ToString();
            int processorCount = Environment.ProcessorCount;

            // Output to verify operations
            Console.WriteLine($"Lowercase: {lowerString}");
            Console.WriteLine($"Uppercase: {upperString}");
            Console.WriteLine($"Trimmed: {trimmedString}");
            Console.WriteLine($"Contains 'Hello': {containsHello}");
            Console.WriteLine($"Replaced String: {replacedString}");
            Console.WriteLine($"Read from file: {readFile}");
            Console.WriteLine($"Encoded string: {encodedString}");
            Console.WriteLine($"Decoded string: {decodedString}");
            Console.WriteLine($"Max number: {maxNumber}");
            Console.WriteLine($"Min number: {minNumber}");
            Console.WriteLine($"Sorted numbers: {string.Join(", ", sortedNumbers)}");
            Console.WriteLine($"Square root of 25: {squareRoot}");
            Console.WriteLine($"2 raised to the power of 3: {power}");
            Console.WriteLine($"Absolute value of -10.5: {absoluteValue}");

            // Clean up
            File.Delete(filePath);


            // Generate EC key pair
            var keyPair = GenerateEcKeyPair();

            // Get private and public keys
            var privateKey = keyPair.Private;
            var publicKey = keyPair.Public;

            // Display keys
            Console.WriteLine("Private Key:");
            //Console.WriteLine(Convert.ToBase64String(privateKey.GetEncoded()));
            Console.WriteLine("\nPublic Key:");
            //Console.WriteLine(Convert.ToBase64String(publicKey.GetEncoded()));

            // Sign a message
            string message = "Hello, BouncyCastle!";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] signature = SignMessage(privateKey, messageBytes);

            // Verify the signature
            bool isVerified = VerifySignature(publicKey, messageBytes, signature);
            Console.WriteLine($"\nSignature Verified: {isVerified}");

            // Generate and display a random number
            var randomNumber = GenerateRandomNumber(32); // Generate a random 32-byte number
            Console.WriteLine($"\nRandom Number: {Convert.ToBase64String(randomNumber)}");


            // Initialize two big integers
            BigInteger bigInt1 = new BigInteger("123456789012345678901234567890");
            BigInteger bigInt2 = new BigInteger("987654321098765432109876543210");

            // Display the big integers
            Console.WriteLine($"Big Integer 1: {bigInt1}");
            Console.WriteLine($"Big Integer 2: {bigInt2}");

            // Perform and display operations
            BigInteger sum = bigInt1.Add(bigInt2);
            Console.WriteLine($"\nSum: {sum}");

            BigInteger difference = bigInt1.Subtract(bigInt2);
            Console.WriteLine($"Difference: {difference}");

            BigInteger product = bigInt1.Multiply(bigInt2);
            Console.WriteLine($"Product: {product}");

            BigInteger quotient = bigInt2.Divide(bigInt1);
            Console.WriteLine($"Quotient: {quotient}");

            BigInteger remainder = bigInt2.Remainder(bigInt1);
            Console.WriteLine($"Remainder: {remainder}");

            // Example of exponentiation
            BigInteger exponentiation = bigInt1.Pow(2); // bigInt1 squared
            Console.WriteLine($"Big Integer 1 squared: {exponentiation}");

            // Example of modulus
            BigInteger mod = bigInt2.Mod(bigInt1);
            Console.WriteLine($"Big Integer 2 modulo Big Integer 1: {mod}");

            Console.Write("Enter a message to hash: ");
            string message2 = Console.ReadLine();

            Console.WriteLine($"MD5: {ComputeMD5(message2)}");
            Console.WriteLine($"SHA1: {ComputeSHA1(message2)}");
            Console.WriteLine($"SHA256: {ComputeSHA256(message2)}");
            Console.WriteLine($"SHA384: {ComputeSHA384(message2)}");
            Console.WriteLine($"SHA512: {ComputeSHA512(message2)}");
            Console.WriteLine($"SHA3-256: {ComputeSHA3(message2, 256)}");
            Console.WriteLine($"SHA3-512: {ComputeSHA3(message2, 512)}");

            string plaintext = "Hello, this is a secret message!";
            byte[] key = GenerateRandomBytes(32); // 256-bit key for ChaCha20/Salsa20
            byte[] nonce = GenerateRandomBytes(8); // 64-bit nonce for Salsa20
            byte[] chaChaNonce = GenerateRandomBytes(12); // 96-bit nonce for ChaCha20

            // Salsa20 Encryption and Decryption
            Console.WriteLine("Salsa20 Encryption:");
            byte[] salsa20Ciphertext = Salsa20Encrypt(plaintext, key, nonce);
            Console.WriteLine($"Ciphertext: {BitConverter.ToString(salsa20Ciphertext).Replace("-", "")}");

            string salsa20Decrypted = Salsa20Decrypt(salsa20Ciphertext, key, nonce);
            Console.WriteLine($"Decrypted: {salsa20Decrypted}");

            // ChaCha20 Encryption and Decryption
            Console.WriteLine("\nChaCha20 Encryption:");
            byte[] chaCha20Ciphertext = ChaCha20Encrypt(plaintext, key, chaChaNonce);
            Console.WriteLine($"Ciphertext: {BitConverter.ToString(chaCha20Ciphertext).Replace("-", "")}");

            string chaCha20Decrypted = ChaCha20Decrypt(chaCha20Ciphertext, key, chaChaNonce);
            Console.WriteLine($"Decrypted: {chaCha20Decrypted}");

            TcpListener server = new TcpListener(IPAddress.Any, Port);
            server.Start();
            Console.WriteLine($"Server started on port {Port}.");

            while (true)
            {
                // Accept a client connection
                var client2 = server.AcceptTcpClient();
                Console.WriteLine("Client connected.");

                // Handle the client in a new task
                Task.Run(() => HandleClient(client2));
            }

            // Start multiple tasks to add to the ConcurrentDictionary
            Task[] tasks = new Task[10];

            for (int i = 0; i < tasks.Length; i++)
            {
                int taskId = i; // Capture the loop variable
                tasks[i] = Task.Run(() => AddToDictionary(taskId));
            }

            // Wait for all tasks to complete
            Task.WaitAll(tasks);

            // Display the contents of the ConcurrentDictionary
            Console.WriteLine("\nContents of ConcurrentDictionary:");
            foreach (var kvp in _concurrentDictionary)
            {
                Console.WriteLine($"Key: {kvp.Key}, Value: {kvp.Value}");
            }
        }

        private static AsymmetricCipherKeyPair GenerateEcKeyPair()
        {
            // Define curve parameters (e.g., P-256)
            //var ecParams = new ECDomainParameters(SecNamedCurves.GetByName("P-256"));
            var Parameters = Org.BouncyCastle.Crypto.EC.CustomNamedCurves.GetByName("secp256k1");
            var ecParams = new ECDomainParameters(Parameters.Curve, Parameters.G, Parameters.N, Parameters.H);            
        
            // Key generation
            var keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 256));

            return keyPairGenerator.GenerateKeyPair();
        }

        private static byte[] SignMessage(ICipherParameters privateKey, byte[] message)
        {
            var signer = SignerUtilities.GetSigner("SHA256withECDSA");
            signer.Init(true, privateKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        private static bool VerifySignature(ICipherParameters publicKey, byte[] message, byte[] signature)
        {
            var signer = SignerUtilities.GetSigner("SHA256withECDSA");
            signer.Init(false, publicKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }

        private static byte[] GenerateRandomNumber(int size)
        {
            // Generate a secure random number
            byte[] randomNumber = new byte[size];
            var secureRandom = new SecureRandom();
            secureRandom.NextBytes(randomNumber);
            return randomNumber;
        }

        static string ComputeMD5(string input)
        {
            //var md5 = new Md5Digest();
            //byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            //md5.BlockUpdate(inputBytes, 0, inputBytes.Length);
            //byte[] hash = new byte[md5.GetDigestSize()];
            //md5.DoFinal(hash, 0);
            return "fail";// BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static string ComputeSHA1(string input)
        {
            var sha1 = new Sha1Digest();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            sha1.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] hash = new byte[sha1.GetDigestSize()];
            sha1.DoFinal(hash, 0);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static string ComputeSHA256(string input)
        {
            var sha256 = new Sha256Digest();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            sha256.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] hash = new byte[sha256.GetDigestSize()];
            sha256.DoFinal(hash, 0);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static string ComputeSHA384(string input)
        {
            var sha384 = new Sha384Digest();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            sha384.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] hash = new byte[sha384.GetDigestSize()];
            sha384.DoFinal(hash, 0);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static string ComputeSHA512(string input)
        {
            var sha512 = new Sha512Digest();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            sha512.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] hash = new byte[sha512.GetDigestSize()];
            sha512.DoFinal(hash, 0);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static string ComputeSHA3(string input, int bitSize)
        {
            IDigest sha3 = bitSize == 256 ? new Org.BouncyCastle.Crypto.Digests.Sha3Digest(256) : new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            sha3.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] hash = new byte[sha3.GetDigestSize()];
            sha3.DoFinal(hash, 0);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static byte[] Salsa20Encrypt(string plaintext, byte[] key, byte[] nonce)
        {
            // Create the Salsa20 engine and parameters
            var salsa20 = new Salsa20Engine();
            var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
            salsa20.Init(true, parameters);

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];

            // Encrypt the plaintext
            salsa20.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, ciphertext, 0);
            return ciphertext;
        }

        static string Salsa20Decrypt(byte[] ciphertext, byte[] key, byte[] nonce)
        {
            var salsa20 = new Salsa20Engine();
            var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
            salsa20.Init(false, parameters);

            byte[] decrypted = new byte[ciphertext.Length];

            // Decrypt the ciphertext
            salsa20.ProcessBytes(ciphertext, 0, ciphertext.Length, decrypted, 0);
            return Encoding.UTF8.GetString(decrypted);
        }

        static byte[] ChaCha20Encrypt(string plaintext, byte[] key, byte[] nonce)
        {
            // Create the ChaCha20 engine and parameters
            var chacha20 = new ChaCha7539Engine();
            var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
            chacha20.Init(true, parameters);

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];

            // Encrypt the plaintext
            chacha20.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, ciphertext, 0);
            return ciphertext;
        }

        static string ChaCha20Decrypt(byte[] ciphertext, byte[] key, byte[] nonce)
        {
            var chacha20 = new ChaCha7539Engine();
            var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
            chacha20.Init(false, parameters);

            byte[] decrypted = new byte[ciphertext.Length];

            // Decrypt the ciphertext
            chacha20.ProcessBytes(ciphertext, 0, ciphertext.Length, decrypted, 0);
            return Encoding.UTF8.GetString(decrypted);
        }

        static byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }
        private static void HandleClient(TcpClient client)
        {
            using (client)
            {
                NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[1024];
                int bytesRead;

                try
                {
                    while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        // Convert the bytes to a string
                        string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        Console.WriteLine($"Received: {message}");

                        // Echo the message back to the client
                        byte[] response = Encoding.UTF8.GetBytes($"Echo: {message}");
                        stream.Write(response, 0, response.Length);
                        Console.WriteLine($"Sent: Echo: {message}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
                finally
                {
                    Console.WriteLine("Client disconnected.");
                }
            }
        }

        private static void AddToDictionary(int taskId)
        {
            for (int i = 0; i < 5; i++)
            {
                int key = taskId * 10 + i; // Unique key for each entry
                string value = $"Value from Task {taskId}, Entry {i}";
                _concurrentDictionary.TryAdd(key, value); // Add to the dictionary
                Console.WriteLine($"Task {taskId} added Key: {key}, Value: {value}");
                Thread.Sleep(100); // Simulate work
            }
        }
    }
}
