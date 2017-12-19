using Invio.Hashing;
using Liphsoft.Crypto.Argon2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ExploringInvioHashing
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = "Gu5DkL8s6MQTSFCtdnYmejHy2KAUcphvxVB4wr7ba9gPzEJ3NR";

            var hasher = new PasswordHasher(UsageEnvironment.Server);

            for (int i = 0; i < 10; i++)
            {
                //var myHashCode = HashCode.From("H6NymcrxLkZMA8dztQTb3BEfeWVuqCwnJ7PXRsD5FSavgpYj2h", key);
                //Console.WriteLine(myHashCode);
                //Console.WriteLine();

                //Hashing without salt.
                string myhash = hasher.Hash("H6NymcrxLkZMA8dztQTb3BEfeWVuqCwnJ7PXRsD5FSavgpYj2h");
                Console.WriteLine(myhash);
                if (hasher.Verify(myhash, "H6NymcrxLkZMA8dztQTb3BEfeWVuqCwnJ7PXRsD5FSavgpYj2h"))
                {
                    Console.WriteLine("Hash Verified!!");
                }

                //password hashing with a random salt
                string salt = GetSalt();
                string myHashWithSalt = hasher.Hash("H6NymcrxLkZMA8dztQTb3BEfeWVuqCwnJ7PXRsD5FSavgpYj2h" + salt);
                Console.WriteLine(myHashWithSalt);
                if (hasher.Verify(myHashWithSalt, "H6NymcrxLkZMA8dztQTb3BEfeWVuqCwnJ7PXRsD5FSavgpYj2h" + salt))
                {
                    Console.WriteLine("hash with salt verified!!!");
                }


                bool isHashUpdated = false;
                string newFormattedHash = null;
                if (hasher.VerifyAndUpdate(myhash, "H6NymcrxLkZMA8dztQTb3BEfeWVuqCwnJ7PXRsD5FSavgpYj2h", out isHashUpdated, out newFormattedHash))
                {
                    //successful login!
                    if (isHashUpdated)
                    {
                        //Update user hash.
                    }
                }
                else
                {
                    //unsuccessful login.
                }

            }


        }

        private static int saltLengthLimit = 32;

        private static string GetSalt()
        {
            return GetSalt(saltLengthLimit);
        }

        private static string GetSalt(int keyLength)
        {
            var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLength];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }
    }
}
