/*
 * This program helps to decrypt files which were encrypted by a Nibiru ransomware variant.
 */

/*
Copyright(C) 2020 Cisco Systems, Inc. and its affiliates

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace NibiruDecryptor
{
    class Decryptor
    {
        /*
         * <summary> Decrpyts the contents of the encrypted file and writes Rijndael-decrypted contents
         * into a different file in the same directory as the encrypted file. </summary>
         * <param name="encrypted_filepath"> The file path of the encrypted fie </param>
         * <param name="decrypted_filepath"> The file path of the decrypted file </param>
         * <param name="key"> The 32-byte Rijndael key </param>
         * <param name="iv"> The 16-byte Rijndael IV </param>
         * <returns> true, if decryption was successful. false, if not. </returns>
         */
        public bool Decrypt(string encrypted_filepath, string decrypted_filepath, byte[] key, byte[] iv)
        {
            // Instantiate file streams
            FileStream fsInput = new FileStream(encrypted_filepath, FileMode.Open, FileAccess.Read);
            long encrypted_filedata_length = fsInput.Length;
            FileStream fsOutput = new FileStream(decrypted_filepath, FileMode.OpenOrCreate, FileAccess.Write);
            fsOutput.SetLength(0L);

            // Create decryptor stream
            RijndaelManaged rijndaelManaged = new RijndaelManaged();
            CryptoStream cryptoStream= new CryptoStream(fsOutput, rijndaelManaged.CreateDecryptor(key, iv), CryptoStreamMode.Write);

            // Decrypt encrypted file contents and write to decrypted_filepath
            for (long index = 0L; index < encrypted_filedata_length; )
            {
                byte[] filedata = new byte[4096];
            
                // Read 4096 bytes of encrypted file contents into filedata
                int bytes_read = fsInput.Read(filedata, 0, 4096);
                // Decrypt and write to output file
                cryptoStream.Write(filedata, 0, bytes_read);

                // Increment to next encrypted block index
                index += unchecked((long)bytes_read);
            }

            try
            {
                cryptoStream.Close();
            }
            catch (CryptographicException err)
            {
                // CryptographicException has been seen when the decryptor is run on a file not encrypted by Rijndael-256
                Console.WriteLine("[*] Error: " + err);
                Console.WriteLine("[*] Skipping file: " + encrypted_filepath);
                fsInput.Close();
                fsOutput.Close();
                return false;
            }

            fsInput.Close();
            fsOutput.Close();

            return true;
        }

        /*
         * <summary> Generates the key and IV value from the seed's SHA512 hash. This will be used in Rijndael-256 decryption. </summary>
         * <param name="seed"> The string used as a seed to generate the key or IV value. </param>
         * <param name="flag"> A boolean value that indicates if key or IV is generated. If true,
         * 32-byte key is generated, else 16-byte IV is generated. </param>
         * <returns> The generated key or IV value to be used in Rijndael-256 decryption </returns>
         */
        public byte[] CreateRijndaelParams(string seed, bool flag)
        {
            // Compute SHA512 hash of seed value
            SHA512Managed sha512Managed = new SHA512Managed();
            byte[] sha512_seed = sha512Managed.ComputeHash(Encoding.ASCII.GetBytes(seed));

            if (flag)
            {
                // key = sha512_seed[:32]
                return sha512_seed.Take(32).ToArray();
            }
            else
            {
                // iv = sha512_seed[32:48]
                return sha512_seed.Skip(32).Take(16).ToArray();
            }
        }
    }
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[-] Decryptor requires the encrypted file as an argument");
                Console.WriteLine("[*] Usage: NibiruDecryptor.exe <encrypted_filepath>");
                return 1;
            }

            Console.WriteLine("[+] This decryptor is applicable to Nibiru ransomware variants " +
                "that use \"Nibiru\" as the seed for generating Rijndael-256 key and IV values");
            Console.WriteLine("[+] Starting Nibiru ransomware decryptor");

            // Accept encrypted filepath as the first cmdline positional argument
            string encrypted_filepath = args[0];
            if (!File.Exists(encrypted_filepath))
            {
                Console.WriteLine("[-] " + encrypted_filepath + " does not exist.");
                Console.WriteLine("[*] Usage: NibiruDecryptor.exe <encrypted_filepath>");
                return 1;
            }
            string decrypted_filepath = Path.Combine(Path.GetDirectoryName(encrypted_filepath), Path.GetFileNameWithoutExtension(encrypted_filepath));
            Console.WriteLine("[+] Encrypted file path: " + encrypted_filepath);
            Console.WriteLine("[+] Decrypted contents will be written to: " + decrypted_filepath);

            var decryptor = new Decryptor();

            // Compute key and IV values using "Nibiru" as the seed
            byte[] key = decryptor.CreateRijndaelParams("Nibiru", true);
            byte[] iv = decryptor.CreateRijndaelParams("Nibiru", false);

            // Decrypt
            if (decryptor.Decrypt(encrypted_filepath, decrypted_filepath, key, iv))
            {
                Console.WriteLine("[+] Decryption complete!");
            }
            else
            {
                Console.WriteLine("[-] Decryption unsuccessful!");
            }
            
            return 1;
        }
    }
}
