package com.crypto.projet;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ValidCertificateTest {

    @Test
    public void testLoadCertificate() throws Exception {
        X509Certificate cert = loadTestCertificate();
        assertNotNull(cert, "Le certificat ne doit pas être null");
    }

    @Test
    public void testIsSelfSigned() throws Exception {
        X509Certificate cert = loadTestCertificate();
        assertTrue(ValidCertificate.isSelfSigned(cert), "Le certificat doit être auto-signé");
    }

    private X509Certificate loadTestCertificate() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream("src/certificates/GlobalSign.crt");
        return (X509Certificate) factory.generateCertificate(fis);
    }
}
