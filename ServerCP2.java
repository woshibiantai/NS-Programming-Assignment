import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServerCP2 {

    public static void main(String[] args) throws Exception {
        ExecutorService exec = Executors.newCachedThreadPool();
        String privateKeyPath = args[0];
        String signedCertificatePath = args[1];
        String hashAlgo = args[2];

        ServerCP2 secStore = new ServerCP2();

        ServerSocket server = new ServerSocket(4321);
        System.out.println(server.getInetAddress().getLocalHost().getHostAddress());
        System.out.println(">> Secure Store is now open!");

        while (true) {
            try {
                Socket client = server.accept();
                secStore.ClientHandling(client, privateKeyPath, signedCertificatePath, hashAlgo);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void ClientHandling(Socket client, String privateKeyPath, String signedCertificatePath, String hashAlgo) throws Exception {
        /**
         ************************************************************************************************
         ********************************************AUTHENTICATION**************************************
         ************************************************************************************************
         */

        // Reading and sending bytes
        OutputStream byteOutput = client.getOutputStream();
        InputStream byteInput =  client.getInputStream();

        // Reading and sending strings
        PrintWriter output = new PrintWriter(client.getOutputStream(), true);
        BufferedReader input = new BufferedReader(
                new InputStreamReader(client.getInputStream()));

        // Initial handshake with client
        System.out.println("Client: " + input.readLine()); // "Hello SecStore, please prove your identity!"
        output.println("Hello, this is SecStore");

        // Getting FRESH nonce from client
        String nonceString = input.readLine();
        BigInteger nonceBigInteger = new BigInteger(nonceString);
        // System.out.println("Client sent nonce: " + nonceString);
        byte[] nonce = nonceBigInteger.toByteArray();
//        System.out.println(">> nonce: " + Arrays.toString(nonce));

        // Encrypting nonce...
        PrivateKey privateKey = GetPrivateKey(privateKeyPath);
        byte[] encryptedNonce = EncryptMessage(nonce, privateKey, hashAlgo);
        BigInteger encryptedBI = new BigInteger(encryptedNonce);

        // Send nonce to client
        output.println(hashAlgo);
        output.println(encryptedBI);
        output.flush();
        System.out.println(">> Sent encrypted nonce hashed using " + hashAlgo + " to client!");
//        System.out.println(">> encrypted nonce: " + encryptedBI);

        // Wait on the Client to send CA request
        String CARequestLine = input.readLine();
        System.out.println(CARequestLine);

        // Check if client is requesting signed certificate
        if (CARequestLine.contains("CA")){
            // Reading signed Certificate into buffer
            File signedCertificate = new File(signedCertificatePath);
            byte[] signedCertificate_byteFormat = new byte[(int) signedCertificate.length()];
            BufferedInputStream CAbufferedInputStream = new BufferedInputStream(new FileInputStream(signedCertificate));
            CAbufferedInputStream.read(signedCertificate_byteFormat,0,signedCertificate_byteFormat.length);

            // Send signed Certificate to client
            output.println(signedCertificate_byteFormat.length);
            System.out.println(input.readLine());
            byteOutput.write(signedCertificate_byteFormat,0,signedCertificate_byteFormat.length);
            System.out.println(">> Sent certificate to client");
//            System.out.println(Arrays.toString(signedCertificate_byteFormat));
            byteOutput.flush();
            output.flush();
            CAbufferedInputStream.close();

        }

        /**
         ************************************************************************************************
         ********************************************FILE TRANSFER**************************************
         ************************************************************************************************
         */

        // Begin File transfer
        System.out.println(">> Starting File Transfer");

        String fileTransferRequest = input.readLine();
        if(fileTransferRequest.contains("File Transfer")){

            receiveAnddecryptFileCP2Standard(output, input, byteInput, privateKey);

            output.println("File Uploaded Successfully");
            output.flush();

            output.close();
            input.close();
            byteInput.close();
            byteOutput.close();
            client.close();
        }
    }

    // Encrypts message given a private key and a hash algorithm, Hash algorithm is to reduce the size of nonce and for added security
    private byte[] EncryptMessage(byte[] m, PrivateKey key, String hashAlgo) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // hashing the nonce due to RSA limitations
        MessageDigest md = MessageDigest.getInstance(hashAlgo);
        md.update(m);
        byte[] digest = md.digest();

        return cipher.doFinal(digest);
    }

    // Gets the private key from file
    private PrivateKey GetPrivateKey(String filePath) throws Exception {
        Path privateKeyPath = Paths.get(filePath);
        byte[] privateKeyByte = Files.readAllBytes(privateKeyPath);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

    // Decryption method by splitting the encrypted file into chunks of appropriate size
    private static void receiveAnddecryptFileCP2Standard(PrintWriter output, BufferedReader input, InputStream byteInput, PrivateKey privateKey) throws Exception{

        // Receive Encrypted AES key from client
        String encryptedAESKey_byteFormatLength = input.readLine();
        output.println("SERVER: Ready to receive encrypted AES Session key");
        output.flush();

        byte[] encryptedAESKey_byteFormat = new byte[Integer.parseInt(encryptedAESKey_byteFormatLength)];
        readByte(encryptedAESKey_byteFormat, byteInput);
        System.out.println("Received Encrypted AES Session key from client ");

        // Receive Encrypted File from client
        String fileName = input.readLine();
        String encryptedFile_byteFormatLength = input.readLine();
        output.println("SERVER: Ready to receive Encrypted File from client ");
        output.flush();
        byte[] encryptedFile_byteFormat = new byte[Integer.parseInt(encryptedFile_byteFormatLength)];
        readByte(encryptedFile_byteFormat,byteInput);
        System.out.println(">> Received encrypted File from client ");

        // Create RSA Cipher object to decrypt AES key
        Cipher rsaCipherDecryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipherDecryption.init(Cipher.DECRYPT_MODE, privateKey);

        // Decrypt encrypted AES key
        byte[] aesKey_byteFormat = rsaCipherDecryption.doFinal(encryptedAESKey_byteFormat);

        // Recreate AES key
        SecretKey aesKey = new SecretKeySpec(aesKey_byteFormat, 0, aesKey_byteFormat.length, "AES");
        System.out.println(">> AES Key successfully decrypted and recreated");

        // Create AES Cipher object to decrypt File
        Cipher aesCipherDecryption = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipherDecryption.init(Cipher.DECRYPT_MODE, aesKey);

        // Decrypt AES encrypted File
        byte[] decryptedFile_byteFormat = aesCipherDecryption.doFinal(encryptedFile_byteFormat);
        System.out.println(">> File successfully Decrypted");

        // create new File and write contents to file
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        fileOutputStream.write(decryptedFile_byteFormat, 0, decryptedFile_byteFormat.length);
        System.out.println("Created new file, " + fileName +", and written to system");

        output.println("File Uploaded Successfully");
        output.flush();
    }

    // Handles the reading of bytes into a given byte array from inputStream
    private static void readByte(byte[] byteArray, InputStream byteIn) throws Exception{
        int offset = 0;
        int numRead;

        try {
            System.out.println("Reading bytes...");
            while (offset < byteArray.length && (numRead = byteIn.read(byteArray, offset, byteArray.length - offset)) >= 0) {
                offset += numRead;
            }
            if (offset < byteArray.length) {
                System.out.println("File reception incomplete!");
            }

        } catch (Exception e) {
            System.out.println("READ ERROR");
        }
    }
}

