import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by woshibiantai on 11/4/17.
 */
public class SecureFileTransfer {
    public static void main(String[] args) throws FileNotFoundException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        SecureFileTransfer s = new SecureFileTransfer();
        s.VerifyCertificate();
    }

    public void VerifyCertificate() throws FileNotFoundException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        InputStream fis = new FileInputStream("/Users/woshibiantai/Downloads/term05/CSE/src/CA.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);

        InputStream mine = new FileInputStream("/Users/woshibiantai/Downloads/term05/CSE/src/1001795.crt");
        X509Certificate ServerCert = (X509Certificate) cf.generateCertificate(mine);

        PublicKey key = CAcert.getPublicKey();

        ServerCert.checkValidity();
        ServerCert.verify(key);
    }
}
