import java.io.*;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by jonathanbeiqiyang on 16/4/17.
 */
class ClientCP1 {
    public static void main(String[] args) throws Exception {
        ClientCP1 cp1Client = new ClientCP1();
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

            //Request CA certificate from the server
            output.println("CLIENT: Please send me your certificate signed by the CA");
            System.out.println(">> Please send me your certificate signed by the CA");

        }
    }

}

