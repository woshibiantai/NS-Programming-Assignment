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

public class CP1SecStore {

    public static void main(String[] args) throws Exception {
        String privateKeyPath = "/Users/woshibiantai/Downloads/term05/CSE/src/privateServer.der";
        String hashAlgo = "MD5";

        CP1SecStore secStore = new CP1SecStore();

        ServerSocket server = new ServerSocket(6789);
        System.out.println("Secure Store is now open!");

        while (true) {
            Socket client = server.accept();
            secStore.ClientHandling(client, privateKeyPath, hashAlgo);
            client.close();
        }
    }

    private void ClientHandling(Socket client, String privateKeyPath, String hashAlgo) throws Exception {
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

class CP1Client {
    public static void main(String[] args) throws Exception {
        CP1Client cp1Client = new CP1Client();
        Socket client = new Socket("localhost", 6789);

        // Reading and sending bytes
        OutputStream byteOutput = client.getOutputStream();
        InputStream byteInput = client.getInputStream();

        // Reading and sending strings
        PrintWriter output = new PrintWriter(byteOutput, true);
        BufferedReader input = new BufferedReader(
                new InputStreamReader(byteInput));

        // Initial handshake with server
        output.println("Hello SecStore, please prove your identity!");
        String confirmation = input.readLine();
        System.out.println("Server: " + confirmation); // "Hello, this is SecStore"

        if (confirmation.equals("Hello, this is SecStore")) {
            // Generate nonce!
            byte[] nonce = new byte[256];
            (SecureRandom.getInstanceStrong()).nextBytes(nonce);
            System.out.println(nonce.length);

            // Send the FRESH nonce to the server
            output.println(nonce.length); // let server know nonce length
            byteOutput.write(nonce);
            byteOutput.flush();
            System.out.println(Arrays.toString(nonce));
            System.out.println("Sent unencrypted nonce to server");

            // Read encrypted nonce from server
            int encryptedLength = Integer.parseInt(input.readLine());
            byte[] encryptedNonce = new byte[encryptedLength];
            String hashAlgo = input.readLine();
            int count = byteInput.read(encryptedNonce);
            System.out.println("Server sent encrypted nonce hashed using "+ hashAlgo + ": " + Arrays.toString(encryptedNonce));
        }
    }

}
