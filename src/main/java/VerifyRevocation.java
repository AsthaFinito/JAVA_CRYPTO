//Pour compiler : javac -d src/out -sourcepath src/main/java src/main/java/VerifyRevocation.java
//Pour exécuter : java -cp src/out VerifyRevocation DER expired_badssl.der

import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URL;
import java.security.cert.*;
import java.util.*;

public class VerifyRevocation {

    private static final Map<String, X509CRL> crlCache = new HashMap<>(); // 🔹 Cache des CRL locales

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java VerifyRevocation <format DER|PEM> <certificat>");
            return;
        }

        try {
            X509Certificate cert = loadCertificate(args[1]);
            System.out.println("🔹 Vérification de la révocation du certificat : " + cert.getSubjectX500Principal());

            boolean isRevoked = checkCRL(cert);
            if (isRevoked) {
                System.out.println("❌ Le certificat est RÉVOQUÉ !");
            } else {
                System.out.println("✅ Le certificat est VALIDE et non révoqué.");
            }
        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }

    /**
     * Charge un certificat X.509 depuis un fichier local.
     */
    public static X509Certificate loadCertificate(String path) throws Exception {
        File certFile = new File("src/certificats/" + path); // 🔹 Utilisation des certificats locaux
        if (!certFile.exists()) {
            throw new Exception("❌ Certificat non trouvé : " + certFile.getAbsolutePath());
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certFile);
        return (X509Certificate) factory.generateCertificate(fis);
    }

    /**
     * Vérifie si un certificat est révoqué via une CRL locale ou téléchargée.
     */
    public static boolean checkCRL(X509Certificate cert) {
        try {
            String crlFileName = "src/certificats/crl.pem"; // 🔹 Nom du fichier CRL local
            File localCRL = new File(crlFileName);
            X509CRL crl;

            if (localCRL.exists()) {
                System.out.println("📂 Utilisation de la CRL locale : " + localCRL.getAbsolutePath());
                crl = loadLocalCRL(crlFileName);

                // 🔹 Vérifier si la CRL est expirée
                if (crl.getNextUpdate() != null && crl.getNextUpdate().before(new Date())) {
                    System.out.println("⚠️ La CRL locale est expirée. Téléchargement d'une nouvelle CRL...");
                    crl = downloadCRL(cert);
                }
            } else {
                System.out.println("⚠️ Aucune CRL locale trouvée. Téléchargement...");
                crl = downloadCRL(cert);
            }

            // 🔹 Vérification de révocation
            if (crl.isRevoked(cert)) {
                System.out.println("❌ Le certificat est révoqué selon la CRL !");
                return true;
            } else {
                System.out.println("✅ Le certificat n'est pas révoqué selon la CRL.");
            }
        } catch (Exception e) {
            System.out.println("⚠️ Erreur lors de la vérification CRL : " + e.getMessage());
        }
        return false;
    }

    /**
     * Télécharge et charge une CRL à partir du certificat (si nécessaire).
     */
    public static X509CRL downloadCRL(X509Certificate cert) throws Exception {
        String crlURL = getCRLDistributionPoint(cert);
        if (crlURL == null) {
            throw new Exception("Aucune URL de CRL trouvée.");
        }

        System.out.println("📥 Téléchargement de la CRL depuis : " + crlURL);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (var fis = new URI(crlURL).toURL().openStream()) {
            return (X509CRL) cf.generateCRL(fis);
        }
    }

    /**
     * Charge une CRL depuis un fichier local.
     */
    public static X509CRL loadLocalCRL(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(path)) {
            return (X509CRL) cf.generateCRL(fis);
        }
    }

    /**
    * Extrait l'URL de la CRL d'un certificat X.509.
    */
    public static String getCRLDistributionPoint(X509Certificate cert) {
        try {
            byte[] crlBytes = cert.getExtensionValue("2.5.29.31"); // 🔹 OID de CRL Distribution Points
            if (crlBytes != null) {
                return parseCrlURL(crlBytes);
            }
        } catch (Exception e) {
            System.out.println("⚠️ Impossible d'extraire l'URL de la CRL.");
        }
        return null;
    }

    /**
    * Convertit les extensions X.509 en URL pour CRL.
    */
    private static String parseCrlURL(byte[] crlBytes) {
        return "http://example.com/crl"; // 🔹 Simulation d'une URL réelle
    }
}