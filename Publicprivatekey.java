package MessageApp;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;

public class Publicprivatekey {
    // Initialize a SecureRandom object to use later
    private static SecureRandom secureRandom = new SecureRandom();

    // Method to generate an RSA key pair with size 2048
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom()); // 2048 key size
        KeyPair pair = generator.generateKeyPair(); // Generate key pairs

        return pair; // Return the key pairs
    }

    // Method to encrypt a plaintext string using RSA public key
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        // Initialize the Cipher for encryption using RSA and public key
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8)); // Encrypt the message

        return Base64.getEncoder().encodeToString(cipherText); // Return the Base64 encoded string
    }

    // Method to decrypt encrypted string using RSA private key
    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        // Decode the Base64 cipherText
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        // Initailize the Cipher for decryption using RSA and private key
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8); // Return the decrypted string
    }

    // Method used to sign a plaintext string using the RSA private key
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        // Initialze the signature with the private key and update the signature
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

        // Sign the data
        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature); // Return the Base64 encoded string
    }

    // Method to verify a signature using RSA public key
    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        // Initialize the signature with verify using public key and update signature
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

        // Convert the Base64 string back into byte array
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        // Verify the signatureBytes and return value
        return publicSignature.verify(signatureBytes);
    }

    // Method used to find the power of a number with mod p
    private static long power(long a, long b, long p) {
        if (b == 1)
            return a;
        else
            return (((long) Math.pow(a, b)) % p);
    }

    // Method used to generate a prime number for the value of P
    public static long generatePrime() {
        long candidate; // Variable to hold possible prime
        boolean isPrime; // Flag to confirm if it is a prime number

        do {
            candidate = Math.abs(secureRandom.nextLong()); // Generate a random non-negative number
            if (candidate % 2 == 0) // If it is even add 1 to make it odd
                candidate++;

            isPrime = checkPrime(candidate); // Check if the number is prime using checkPrime method
        } while (!isPrime); // Repeat until prime number is found

        return candidate; // Return the prime number
    }

    // Method used to check to see if the generated number is prime
    private static boolean checkPrime(long number) {
        // 0 and 1 are not prime, 2 and 3 are
        if (number <= 1)
            return false;
        if (number <= 3)
            return true;
        // Eliminate numbers divisible by 2 and 3
        if (number % 2 == 0 || number % 3 == 0)
            return false;
        // Check for factors up to the square root
        for (long i = 5; i * i <= number; i += 6) {
            // Check to se if it is divisible by i or i + 2
            if (number % i == 0 || number % (i + 2) == 0) {
                return false;
            }
        }
        return true;
    }

    public static void main(String[] args) throws Exception {
        // Initialize a SecureRandom object to use later
        SecureRandom SecureRandom = new SecureRandom();

        long P, G, x, a, y, b, ka, kb, R1, R2;
        P = generatePrime(); // G and P values agreed between alice and bob
        G = 2;
        System.out.println("P = " + P + " G = " + G);

        a = SecureRandom.nextLong(P) + 1; // a and b private keys for g^ab mod p
        b = secureRandom.nextLong(P) + 1;
        while (b == a) { // If the private keys are the same value regenerate b
            b = secureRandom.nextInt(47) + 1;
        }
        System.out.println("a = " + a + " b = " + b);

        x = power(G, a, P); // g^a mod p
        y = power(G, b, P); // g^b mod p
        System.out.println("x = " + x + " y = " + y);

        ka = power(y, a, P); // g^ab mod p for alice
        kb = power(x, b, P); // g^ab mod p for bob
        System.out.println("ka = " + ka + " kb = " + kb);

        R1 = SecureRandom.nextLong();
        System.out.println("R1 = " + R1);

        R2 = SecureRandom.nextLong();
        System.out.println("R2 = " + R2);

        // First generate a public/private key pair
        KeyPair Alice = generateKeyPair(); // Alice pair keys
        KeyPair Bob = generateKeyPair(); // Bobs pair keys

        // Message 1 = "user 1",R1
        System.out.println("Message 1 A -> B = Im Alice,R1 = " + R1);
        System.out.println();

        // Message 2 = R2+"[{R1, g^b mod p}alice]bob"
        System.out.println("Message 2 A <- B = R2+[{R1, g^b mod p}alice]bob");
        // ENCRYPTION1 = {"R1,g^b mod p"} ALICE KEY
        // SIGNATURE = [{"R1,g^b mod p"} ALICE PUBLIC KEY]BOB SIGNATURE
        String R1gbmodp = Long.toString(R1) + Long.toString(y); // Encrypting R1,g^b mod p with alices public key

        // Encrypt the message
        String encrypR1gbmodp = encrypt(R1gbmodp, Alice.getPublic()); // Encrypting R1,g^b mod p with alices public key
        // signing {"R1,g^b mod p"} with bobs key pairs and verifying signature
        String signatureBob = sign(encrypR1gbmodp, Bob.getPrivate());
        // signing {"R1,g^b mod p"} with bobs key pairs and verifying signature
        boolean isBobCorrect = verify(encrypR1gbmodp, signatureBob, Bob.getPublic());
        System.out.println("Signature correct? " + isBobCorrect);

        // Message 3 = [{R2, g^a mod p}bob]alice
        System.out.println();
        System.out.println("Message 3 A -> B = [{R2, g^a mod p}bob]alice");
        String R2gamodp = Long.toString(R2) + Long.toString(x);
        String encrypR2gamodp = encrypt(R2gamodp, Bob.getPublic()); // Encrypting R2,g^a mod p with bobs public key
        // signing {"R2,g^a mod p"} with alices key pairs and verifying signature
        String signatureA = sign(encrypR2gamodp, Alice.getPrivate());
        // Let's check the signature
        // signing {"R1,g^b mod p"} with bobs key pairs and verifying signature
        boolean isAliceCorrect = verify(encrypR2gamodp, signatureA, Alice.getPublic());
        System.out.println("Signature correct? " + isAliceCorrect);

        System.out.println();
        // Message 4 = session key g^ab mod p stablished
        System.out.println("Alice's Key = " + ka + " Bob's Key = " + kb);
        long sessionKey = ka;
        SecureMessageApp.setKey(Long.toString(sessionKey));
        // System.out.println("Updating session key in SecureMessageApp."); // DEBUG
        SecureMessageApp.main(null);

    }

}
