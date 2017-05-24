package sample;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by jonathanbeiqiyang on 16/4/17.
 */
public class ClientCP2 {

    public static void main(String[] args) throws Exception {
        String certificateCAPath = args[0];
        String filePath = args[1];
        String serverIP = args[2];

        Socket client = new Socket(serverIP, 4321);

        // Reading and sending bytes
        OutputStream byteOutput = client.getOutputStream();
        InputStream byteInput = client.getInputStream();

        // Reading and sending strings
        PrintWriter output = new PrintWriter(client.getOutputStream(), true);
        BufferedReader input = new BufferedReader(
                new InputStreamReader(client.getInputStream()));

        /**
         ************************************************************************************************
         ********************************************AUTHENTICATION**************************************
         ************************************************************************************************
         */

        // Initial handshake with server
        output.println("Hello SecStore, please prove your identity!");
        String confirmation = input.readLine();
        System.out.println("Server: " + confirmation); // "Hello, this is SecStore"

        if (confirmation.contains("this is SecStore")) {
            // Generate nonce!
            SecureRandom random = new SecureRandom();
            BigInteger nonce = new BigInteger(130, random);

            // Send the FRESH nonce to the server
            output.println(nonce);
            output.flush();
            System.out.println(nonce);
            System.out.println(">> Sent unencrypted nonce to server");

            // Read encrypted nonce from server
            String hashAlgo = input.readLine();
            String encryptedNonce = input.readLine();
            BigInteger encryptedBI = new BigInteger(encryptedNonce);

            System.out.println("Server sent encrypted nonce hashed using "+ hashAlgo);
            // System.out.println(">> enrypted nonce: " encryptedBI);

            // Request signed certificate from the server
            output.println("CLIENT: Please send me your certificate signed by the CA");
            System.out.println(">> Please send me your certificate signed by the CA");
            output.flush();

            // Receive signed certificate from the server
            int signedCert_length = Integer.parseInt(input.readLine());
            output.println("READY to receive Certificate!");
            output.flush();
            byte[] signedCert_byteFormat = new byte[signedCert_length];
            readByte(signedCert_byteFormat, byteInput);

            System.out.println(">> Received signed Certificate from server");
//            System.out.println(Arrays.toString(signedCert_byteFormat));

            // Extract public key from CA certificate
            InputStream CAinputStream = new FileInputStream(certificateCAPath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificateCA = (X509Certificate) certificateFactory.generateCertificate(CAinputStream);
            PublicKey publicKeyCA = certificateCA.getPublicKey();
            System.out.println(">> Extracted public key from CA certificate");
            CAinputStream.close();

            // Verify signed certificate using CA's public key
            InputStream certificateInputStream = new ByteArrayInputStream(signedCert_byteFormat);
            X509Certificate signedCertificate = (X509Certificate) certificateFactory.generateCertificate(certificateInputStream);
            signedCertificate.checkValidity();
            signedCertificate.verify(publicKeyCA);
            System.out.println(">> Verified & validated signed certificate!");

            // Extract the public key from server's Signed certificate
            PublicKey publicKeyServer = signedCertificate.getPublicKey();

            // Create and initialize Cipher
            Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decrypt.init(Cipher.DECRYPT_MODE, publicKeyServer);

            // Decrypt nonce
            byte[] decryptedNonce = decrypt.doFinal(encryptedBI.toByteArray());

            if(nonce == new BigInteger(decryptedNonce)){
                System.out.println(">> Identify of server verified!");
            }

            /**
             ************************************************************************************************
             ********************************************FILE TRANSFER**************************************
             ************************************************************************************************
             */

            // Begin file transfer
            output.println("Starting File Transfer");
            System.out.println(">> Starting File Transfer...");

            // Get Starting Time
            Long startTime = System.currentTimeMillis();

            // Encrypt AES Key and File to be sent & Handle uploading

            encryptAndSendFileCP2Standard(output, input, publicKeyServer, byteOutput, filePath);
//            System.out.println(">> File sent to server: " + Arrays.toString(encryptedFile));

            // Check for confirmation from server
            if(input.readLine().contains("File Uploaded Successfully")){
                System.out.println(">> File uploaded successfully");
            }

            Long endTime = System.currentTimeMillis();
            Long totalTime = endTime - startTime;

            System.out.println(">> Total Time spent on operation is: " + totalTime);

            byteInput.close();
            byteOutput.close();
            output.close();
            input.close();
//
            client.close();
        }
    }

    // Method to handle encryption of given file to be sent to server, with a chosen cipher
    private static void encryptAndSendFileCP2Standard(PrintWriter output, BufferedReader input, PublicKey serverPublicKey, OutputStream byteOutput, String filePath) throws Exception{
        // Initiate Cipher object for key encryption, using ENCRYPT mode and server's PUBLIC Key
        Cipher rsaCipherEncryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipherEncryption.init(Cipher.ENCRYPT_MODE, serverPublicKey);

        // Generate AES Key (for encryption of file)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey aesKey = keyGenerator.generateKey();

        // Convert aesKey into byte[] to be sent to server
        byte[] aesKey_byteFormat = aesKey.getEncoded();

        // Encrypt aesKey using RSA
        byte[] encryptedAesKey_byte_format = rsaCipherEncryption.doFinal(aesKey_byteFormat);

        // Initiate Cipher Object for file encryption, using ENCRYPT mode and server's PUBLIC key
        Cipher aesCipherEncryption = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipherEncryption.init(Cipher.ENCRYPT_MODE, aesKey);

        // Convert File to byteformat for file transfer
        File file = new File(filePath);
        byte[] file_byteFormat = new byte[(int) file.length()];
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
        bufferedInputStream.read(file_byteFormat, 0, file_byteFormat.length);

        // Encrypt fileBytes using AES key
        byte[] encryptedFile_byteFormat = aesCipherEncryption.doFinal(file_byteFormat);

        // Send RSA encrypted AES Key to Server
        output.println(encryptedAesKey_byte_format.length);
        output.flush();
        System.out.println(input.readLine()); // "SERVER: Ready to receive Encrypted File from client "
        byteOutput.write(encryptedAesKey_byte_format, 0, encryptedAesKey_byte_format.length);
        byteOutput.flush();
        System.out.println(">> Encrypted AES session key has been sent to server!");

        // Uploaded AES encrypted File to server
        output.println(file.getName());
        output.println(encryptedFile_byteFormat.length);
        output.flush();
        System.out.println(input.readLine());
        byteOutput.write(encryptedFile_byteFormat, 0, encryptedFile_byteFormat.length);
        byteOutput.flush();
        System.out.println(">> Sent encrypted File to server!");

    }

    // Handles the reading of bytes into a given byte array from inputStream
    private static void readByte(byte[] byteArray, InputStream byteIn) throws Exception {
        int offset = 0;
        int numRead;
        try {
            System.out.println(">> readByte working...");
            while (offset < byteArray.length && (numRead = byteIn.read(byteArray, offset, byteArray.length - offset)) >= 0) {

                offset += numRead;
            }
            if (offset < byteArray.length) {
                System.out.println("File reception incomplete!");
            }
        } catch (IOException e) {
            System.out.println("READ ERROR!!!!");
        }
        System.out.println("readByte command Completed!");
    }

}

