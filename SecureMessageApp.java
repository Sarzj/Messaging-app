package MessageApp;

import java.util.HashMap;
import java.util.Scanner;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class SecureMessageApp {
    // Set encryption to Blowfish using CBC with padding
    private static final String BLOWFISH_CBC_PKCS5 = "Blowfish/CBC/PKCS5Padding";
    // Create a hashmap to store users
    private static HashMap<String, String> userDatabase = new HashMap<>();
    // Initialize the secretKey variable
    private static SecretKeySpec secretKey;

    // Set username and password for the users
    static {
        userDatabase.put("Alice", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"); // password
        userDatabase.put("Bob", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"); // 123456
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in); // Open the scanner for user input
        String programStart; // Initialize the programStart variable

        // Start an infinite loop that ends when user uses X to break loop
        while (true) {
            System.out.print("Do you want to Login or Exit? (L/X): "); // Prompt user for first options menu
            programStart = scanner.nextLine().toUpperCase(); // Get user input, change to uppercase

            // If user inputs L, prompt user and get user input
            if ("L".equals(programStart)) {
                System.out.print("Enter Username: ");
                String username = scanner.nextLine();
                System.out.print("Enter Password: ");
                String password = scanner.nextLine();

                // Calls authenticateUser method to see if username and password match HashMap
                if (authenticateUser(username, password)) {
                    System.out.println("Login Successful!");
                    boolean loggedIn = true; // Gives the user access to further operation
                    while (loggedIn) { // While loggedIn prompt user for second options menu
                        System.out.print("Do you want to Encrypt, Decrypt or Logout? (E/D/L): ");
                        String operation = scanner.nextLine().toUpperCase(); // Get user input, change to uppercase

                        // If user inputs E, prompt user and get user input and start Encryption process
                        if ("E".equals(operation)) {
                            System.out.print("Enter message to encrypt: ");
                            String message = scanner.nextLine(); // Sets the input to variable "message"
                            String encryptedMessage = encrypt(message); // Uses the method encrypt on "message"
                            // DEBUG
                            // System.out.println("Encrypted: " + encryptedMessage);

                            // Prompt for recipients username and gets input
                            System.out.print("Enter recipient username: ");
                            String recipient = scanner.nextLine();
                            // If specified user is in userDatabase, write to file
                            if (userDatabase.containsKey(recipient)) {
                                writeFile(recipient + "_encrypted_message.txt", encryptedMessage.getBytes());
                                System.out.println("Encrypted message saved to file.");
                            } else {
                                System.out.println("Recipient not found!");
                            }
                            // loggedIn = false; // Log out after operation
                            // If user inputs E, prompt user and get user input and start Decryption process
                        } else if ("D".equals(operation)) {
                            System.out.print("Enter the filename of the encrypted message to decrypt: ");
                            String filename = scanner.nextLine();
                            byte[] encryptedData = readFile(filename); // Calls readFile to read array of bytes
                            // If file is found, call decrypt method and output to terminal
                            if (encryptedData != null) {
                                String decryptedMessage = decrypt(encryptedData);
                                System.out.println("Decrypted Message: " + decryptedMessage);
                            } else {
                                System.out.println("File not found!");
                            }
                            // loggedIn = false; // Log out after operation
                        } else if ("L".equals(operation)) {
                            System.out.println("Logging out!");
                            loggedIn = false; // Log out after operation
                            break;
                        } else {
                            System.out.println("Invalid choice! Please choose E or D.");
                        }
                    }
                    // If authenticateUser fails, output failed login
                } else {
                    System.out.println("Login Failed!");
                }
                // If user inputs X, break loop
            } else if ("X".equals(programStart)) {
                break;
                // If unexpected input, output correct options
            } else {
                System.out.println("Invalid choice! Please choose L or X.");
            }
        }

        scanner.close(); // Close scanner after the loop
        System.exit(0); // Exits program gracefully
    }

    // Method to check entered username and password in database
    private static boolean authenticateUser(String username, String password) {
        try {
            // If username doesnt match database entry return false
            if (!userDatabase.containsKey(username)) {
                return false;
            }
            // Get the passwordHash connected to the provided username
            String storedPasswordHash = userDatabase.get(username);
            // Hash the provided password using hashPassword method
            String enteredPasswordHash = hashPassword(password);
            // See if the two hashes match
            return storedPasswordHash.equals(enteredPasswordHash);
            // Catch any errors when trying to hash and return false
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Failed to hash password: " + e.getMessage());
            return false;
        }
    }

    // Method to hash the user entered password
    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        // Creating a MessageDigest instance for hashing using SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // Converts the user entered password into bytes
        byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
        // Convert the hashed bytes into a BigInteger
        BigInteger num = new BigInteger(1, hashedPassword);
        // Convert the BigInteger into string
        String hashtext = num.toString(16);
        // Make sure hash is length of 32, add zeros if not
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }
        return hashtext;
    }

    // Method to encrypt the user input string using Blowfish and hash message
    public static String encrypt(String strToEncrypt) {
        // If the secretKey is not set output error message
        if (secretKey == null) {
            System.out.println("Encryption key is not set.");
            return null;
        }
        try {
            // Generate the hash for the user input message for integrity and output it
            String originalHash = hashMessage(strToEncrypt);
            // DEBUG
            // System.out.println("Original: " + originalHash);

            // Initialize Cipher using Blowfish in CBC mode with padding
            Cipher cipher = Cipher.getInstance(BLOWFISH_CBC_PKCS5);
            byte[] iv = new byte[cipher.getBlockSize()]; // Create a byte array for IV
            new SecureRandom().nextBytes(iv); // Randonmly make IV with secureRandom
            IvParameterSpec ivParams = new IvParameterSpec(iv); // Create an IV parameter from the previous byte array
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams); // Initialize the cipher using all previous info
            byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)); // Encrypt the message

            // Create byte array to hold the IV and the encrypted message
            byte[] encryptedIVAndText = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, encryptedIVAndText, 0, iv.length); // Copy IV to array
            System.arraycopy(encrypted, 0, encryptedIVAndText, iv.length, encrypted.length); // Copy message to array

            // Encode the IV and encrypted message as Base64
            String encryptedData = Base64.getEncoder().encodeToString(encryptedIVAndText);
            return encryptedData + "::" + originalHash; // Return encrypted data and original message hash
            // Catch any errors while hashing and output error message
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.getMessage());
            return null;
        }
    }

    // Method to decrypt the encrypted file and check if hashes match
    private static String decrypt(byte[] encryptedWithHash) {
        // Convert the byte array into a string
        String dataString = new String(encryptedWithHash, StandardCharsets.UTF_8);
        // Find the last ::, which seperates encrypted messange and hash
        int delimiterIndex = dataString.lastIndexOf("::");
        // Extract the encrypted data and the original hash
        String encryptedData = dataString.substring(0, delimiterIndex);
        String originalHash = dataString.substring(delimiterIndex + 2);

        // Decode the Base64 encoded data
        byte[] encryptedIVTextBytes = Base64.getDecoder().decode(encryptedData);
        try {
            // Initialize the cipher for decryption using Blowfish with CBC and padding
            Cipher cipher = Cipher.getInstance(BLOWFISH_CBC_PKCS5);
            // Extract the IV from position 0-8 in the byte array
            byte[] iv = Arrays.copyOfRange(encryptedIVTextBytes, 0, 8);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            // Extract the encrypted message after the extracted IV
            byte[] encryptedText = Arrays.copyOfRange(encryptedIVTextBytes, iv.length, encryptedIVTextBytes.length);
            // Use the initialized cipher to decrypt using the secretKey and IV
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
            // Perform the decryption
            byte[] decrypted = cipher.doFinal(encryptedText);
            // Convert the byte array back into a string
            String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

            // Check to see if the hashes of the two messages match
            // DEBUG
            // System.out.println("Decrypted: " + hashMessage(decryptedMessage));
            if (hashMessage(decryptedMessage).equals(originalHash)) {
                System.out.println("Hashes match: The decrypted message is authentic and unchanged.");
            } else {
                System.out.println("Hashes do not match: The decrypted message may have been altered or corrupted.");
            }

            return decryptedMessage;
            // Catch any errors while decrypting and output error message
        } catch (Exception e) {
            System.out.println("Error while decrypting!");
            return null;
        }
    }

    // Method used to create a hash for the input messages
    private static String hashMessage(String message) {
        try {
            // Creating a MessageDigest instance for hashing using SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Convert the input message into a byte array
            byte[] hashedMessage = md.digest(message.getBytes(StandardCharsets.UTF_8));
            // Convert the hashed byte array into a BigInteger
            BigInteger num = new BigInteger(1, hashedMessage);
            // Convert to string and return it
            return num.toString(16);
            // Catch any errors that occur when hashing and output error messge
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Failed to hash message: " + e.getMessage());
            return null;
        }
    }

    // Method to set the secret key generated by Publicprivatekey.java
    static void setKey(String sessionKey) {
        // Check to see if the session key has been set, return error if so
        if (sessionKey == null || sessionKey.isEmpty()) {
            System.out.println("Invalid session key provided.");
            return;
        }
        try {
            // Conver the session key into a byte array
            byte[] key = sessionKey.getBytes("UTF-8");
            // Make sure the array is of size 16
            key = Arrays.copyOf(key, 16);
            // Using Blowfish create a SecretKeySpec for the secretKey
            secretKey = new SecretKeySpec(key, "Blowfish");
            // DEBUG
            // System.out.println("Key Updated: " + bytesToHex(secretKey.getEncoded()));
            // Catch any errors and output error message
        } catch (Exception e) {
            System.out.println("Error setting key: " + e.getMessage());
        }
    }

    // Method used to read bytes from a file
    private static byte[] readFile(String filename) {
        try {
            // Read all of the bytes according to the filename given
            return Files.readAllBytes(Paths.get(filename));
            // Catch any errors and output error message
        } catch (Exception e) {
            System.out.println("Error reading file: " + e.getMessage());
            return null;
        }
    }

    // Method used to write to a file
    private static void writeFile(String filename, byte[] data) {
        // Use FileOutputStream which will be used to write to the file with filename
        try (FileOutputStream outputStream = new FileOutputStream(new File(filename))) {
            // Write the byte array to the file
            outputStream.write(data);
            // Catch any errors and output eror message
        } catch (Exception e) {
            System.out.println("Error writing file: " + e.getMessage());
        }
    }

    // Method to convert a byte array into a string
    // Used for DEBUG message
    // private static String bytesToHex(byte[] bytes) {
    // // Create a StringBuilder to use for making string
    // StringBuilder sb = new StringBuilder();
    // // Loop through each byte in the byte array
    // for (byte b : bytes) {
    // // Append each byte into a 2 digit hex number
    // sb.append(String.format("%02X", b));
    // }
    // // Return the completed string
    // return sb.toString();
    // }
}
