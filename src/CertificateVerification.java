import com.sun.tools.doclets.internal.toolkit.util.DocFinder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by jonathanbeiqiyang on 10/4/17.
 */
public class CertificateVerification {





    public CertificateVerification() throws FileNotFoundException, CertificateException {
    }

    public static void main(String[] args) throws FileNotFoundException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        InputStream fis = new FileInputStream("/Users/jonathanbeiqiyang/IdeaProjects/SecureFileTransferProject/src/1001619.crt");
        InputStream CAInput = new FileInputStream("/Users/jonathanbeiqiyang/IdeaProjects/SecureFileTransferProject/src/CA.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate ServerCert = (X509Certificate) cf.generateCertificate(fis);
        X509Certificate CACert = (X509Certificate) cf.generateCertificate(CAInput);
        PublicKey publicKey = CACert.getPublicKey();


        ServerCert.checkValidity();
        ServerCert.verify(publicKey);

    }
}
