package sample;

import javax.crypto.Cipher;
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

public class ServerCP1 {

    public static void main(String[] args) throws Exception {
        ExecutorService exec = Executors.newCachedThreadPool();
        String privateKeyPath = args[0];
        String signedCertificatePath = args[1];
        String hashAlgo = args[2];

        ServerCP1 secStore = new ServerCP1();

        ServerSocket server = new ServerSocket(4321);
        System.out.println(server.getInetAddress().getLocalHost().getHostAddress());
        System.out.println(">> Secure Store is now open!");

        while (true) {
            Socket client = server.accept();
            exec.execute(() -> {
                try {
                    secStore.ClientHandling(client, privateKeyPath, signedCertificatePath, hashAlgo); // privateKeyPath, hashAlgo, signedCertificatePath
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
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
            // Reading signed Certificate into signedCertificate_byteFormat
            File signedCertificate = new File(signedCertificatePath);
            byte[] signedCertificate_byteFormat = new byte[(int) signedCertificate.length()];
            BufferedInputStream CAbufferedInputStream = new BufferedInputStream(new FileInputStream(signedCertificate));
            CAbufferedInputStream.read(signedCertificate_byteFormat,0,signedCertificate_byteFormat.length);

            // Send signed Certificate to client
            output.println(signedCertificate_byteFormat.length);
            System.out.println(input.readLine()); // "READY to receive Certificate!"

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

            // create cipher object, initialize to decrypt mode, using Private Key
            Cipher rsaCipherDecryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipherDecryption.init(Cipher.DECRYPT_MODE, privateKey);

            // initiate file transfer
            String fileName = input.readLine();
            String fileLength = input.readLine();

            output.println("SERVER: Ready to receive encrypted file!");
            output.flush();

            byte[] decryptedHoldFile = new byte[Integer.parseInt(fileLength)];
            readByte(decryptedHoldFile, byteInput);
            System.out.println("File received from client successfully");
            System.out.println("Decrypting encrypted file received from client...");
            byte[] decryptedFile = decryptFileCP1Standard(decryptedHoldFile, rsaCipherDecryption);
//            System.out.println("Decrypted file: " + Arrays.toString(decryptedFile));

            // create new File and write contents to file
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            fileOutputStream.write(decryptedFile, 0, decryptedFile.length);
            System.out.println("Created new file, " + fileName +", and written to system");

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
    private static byte[] decryptFileCP1Standard(byte[] data, Cipher cipher) throws Exception{
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int count = 0;

        while(count < data.length){
            byte[] buffer;
            if (data.length - count >= 128) {
                buffer = cipher.doFinal(data, count, 128);
            } else{
                buffer = cipher.doFinal(data, count, data.length - count);
            }
            byteArrayOutputStream.write(buffer, 0, buffer.length);
            count += 128;
        }

        byte[] decryptedFile_byteFormat = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();

        return decryptedFile_byteFormat;

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

