import sun.plugin2.message.Message;
import sun.security.provider.MD5;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by woshibiantai on 11/4/17.
 */

public class ServerCP1 {
    String privateKeyPath = "/Users/jonathanbeiqiyang/IdeaProjects/SecureFileTransferProject/CP1/src/privateServer.der";
    String certificateCAPath = "/Users/jonathanbeiqiyang/IdeaProjects/SecureFileTransferProject/CP1/src/CA.crt";
    String hashAlgo = "MD5";

    public static void main(String[] args) throws Exception {


        ServerCP1 secStore = new ServerCP1();

        ServerSocket server = new ServerSocket(6789);
        System.out.println("Secure Store is now open!");

        while (true) {
            Socket client = server.accept();
            secStore.ClientHandling(client, privateKeyPath, hashAlgo);
            client.close();
        }
    }

    private void ClientHandling(Socket client, String privateKeyPath, String hashAlgo) throws Exception {
        /**
         ************************************************************************************************
         ********************************************AUTHENTICATION**************************************
         ************************************************************************************************
         */

        // Reading and sending bytes
        OutputStream byteOutput = client.getOutputStream();
        InputStream byteInput = client.getInputStream();

        // Reading and sending strings
        PrintWriter output = new PrintWriter(byteOutput, true);
        BufferedReader input = new BufferedReader(
                new InputStreamReader(byteInput));

        // Initial handshake with client
        System.out.println("Client: " + input.readLine()); // "Hello SecStore, please prove your identity!"
        output.println("Hello, this is SecStore");

        // Getting FRESH nonce from client
        int nonceLength = Integer.parseInt(input.readLine());
        byte[] nonce = new byte[nonceLength];
        int count = byteInput.read(nonce);
        System.out.println("Client sent nonce: " + Arrays.toString(nonce));

        // Encrypting nonce...
        PrivateKey privateKey = GetPrivateKey(privateKeyPath);
        byte[] encryptedNonce = EncryptMessage(nonce, privateKey, hashAlgo);

        // Send nonce to client
        output.println(encryptedNonce.length);
        output.println(hashAlgo);
        output.flush();
        byteOutput.write(encryptedNonce);
        byteOutput.flush();
        System.out.println("Sent encrypted nonce hashed using " + hashAlgo + " to client!");
        System.out.println(Arrays.toString(encryptedNonce));

        //Wait on the Client to send CA request
        String CARequestLine = input.readLine();
        if(CARequestLine.contains("CA")){
            System.out.println("Client Requesting CA Certificate");

            //Send CA Certificate to Client
            File certificateCA = new File(certificateCAPath);
            File 
        }
    }

    private byte[] EncryptMessage(byte[] m, PrivateKey key, String hashAlgo) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // hashing the nonce due to RSA limitations
        MessageDigest md = MessageDigest.getInstance(hashAlgo);
        md.update(m);
        byte[] digest = md.digest();

        return cipher.doFinal(digest);
    }

    private PrivateKey GetPrivateKey(String filePath) throws Exception {
        Path privateKeyPath = Paths.get(filePath);
        byte[] privateKeyByte = Files.readAllBytes(privateKeyPath);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

}

