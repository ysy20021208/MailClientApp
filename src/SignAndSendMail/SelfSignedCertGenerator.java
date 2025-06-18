package SignAndSendMail;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SelfSignedCertGenerator {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String email = "alice@z.eshark.cc";
        String password = "123456";
        String p12Path = ".\\certs\\untrusted-alice.p12";

        // 生成密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=" + email);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        pkcs12.load(null, null);
        pkcs12.setKeyEntry("private", keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{cert});

        try (FileOutputStream out = new FileOutputStream(p12Path)) {
            pkcs12.store(out, password.toCharArray());
        }

        System.out.println("✅ 已为 " + email + " 生成自签名证书：" + p12Path);
    }
}
