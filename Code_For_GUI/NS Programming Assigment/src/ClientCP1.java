import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by jonathanbeiqiyang on 16/4/17.
 */
class ClientCP1 {

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
//            System.out.println(">> Nonce: " + nonce);
            System.out.println(">> Sent unencrypted nonce to server");

            // Read encrypted nonce from server
            String hashAlgo = input.readLine();
            String encryptedNonce = input.readLine();
            BigInteger encryptedBI = new BigInteger(encryptedNonce);

            System.out.println("Server sent encrypted nonce hashed using " + hashAlgo);
//            System.out.println(">> encrypted nonce: " + encryptedBI);

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

            // create cipher object, initialize to encrypt mode, using Server's Public Key
            Cipher rsaCipherEncryption = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipherEncryption.init(Cipher.ENCRYPT_MODE, publicKeyServer);

            // Encrypt File to be sent
            File file = new File(filePath);
            byte[] encryptedFile = encryptFileCP1Standard(filePath, rsaCipherEncryption);
//            System.out.println("File sent to server: " + Arrays.toString(encyptedFile));

            // Initiate File Transfer
            output.println(file.getName());
            output.println(encryptedFile.length);
            System.out.println(input.readLine());
            byteOutput.write(encryptedFile, 0, encryptedFile.length);

            byteOutput.flush();

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
    private static byte[] encryptFileCP1Standard(String filename, Cipher cipher) throws Exception{
        Path path = Paths.get(filename);
        byte[] data = Files.readAllBytes(path);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int count = 0;
        while(count < data.length){
            byte[] buffer;
            if (data.length - count >= 117){
                buffer = cipher.doFinal(data, count, 117);
            } else {
                buffer = cipher.doFinal(data, count, data.length - count);
            }
            byteArrayOutputStream.write(buffer, 0, buffer.length);
            count += 117;
        }
        byte[] encryptedFile_byteFormat = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();

        return encryptedFile_byteFormat;
    }

    // Handles the reading of bytes into a given byte array from inputStream
    private static void readByte(byte[] byteArray, InputStream byteIn) throws Exception {
        int offset = 0;
        int numRead;
        try {
            System.out.println("readByte working...");
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

