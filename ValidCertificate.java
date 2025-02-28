import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

public class ValidCertificate {
    public static void main(String[] args) {
        processArguments(args);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(args[2]);//TODO multiple filename
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();
            System.out.println("Numéro de série : " + cert.getSerialNumber());
            PublicKey publicKey = cert.getPublicKey();
            System.out.println("Clé publique : " + publicKey);
            System.out.println("Algo : " + cert.getSigAlgName());
            if (isSelfSigned(cert)) {
                System.out.println("Le certificat est auto-signé.");
            } else {
                System.out.println("Le certificat n'est pas auto-signé.");
            }
            cert.verify(publicKey);//A MODIF
            System.out.println("Sujet : " + cert.getSubjectX500Principal());
            System.out.println("Émetteur : " + cert.getIssuerX500Principal());
            checkKeyUsage(cert);
            checkValidityPeriod(cert);
            checkSignatureAPICrypto(cert,publicKey,cert.getSigAlgName(),cert.getSignature());
        } catch (Exception e) {
            System.err.println("Erreur lors de la lecture du certificat : " + e.getMessage());
        }
    }

    /**
     * Processes the command line arguments for certificate validation.
     * 
     * The method expects exactly three arguments. The first argument must be the
     * string "-format", the second argument must be either "DER" or "PEM" to specify
     * the certificate format, and the third argument must be the path to a 
     * certificate file. If the arguments do not meet these criteria, the method 
     * prints an error message and returns.
     * 
     * @param args The array of command line arguments.
     */

    public static void processArguments(String[] args) {
        System.out.println("Hello, World!");
        
        if (args.length != 3) {
            System.out.println("Format à respecter : -format <DER|PEM> <NameFile>");
            return;
        }
        
        System.out.println("Arguments: " + Arrays.toString(args));
        
        if ((!args[0].equals("-format")) || (!args[1].equals("DER") && !args[1].equals("PEM"))) {
            System.out.println("Erreur : First flag incorrect");
            return;
        }
        
        File certFile = new File(args[2]);
        if (!certFile.exists() || !certFile.isFile()) {
            System.out.println("Erreur : Le fichier spécifié n'existe pas ou n'est pas un fichier valide.");
            return;
        }
    }

    /**
     * Checks if the given X509 certificate is self-signed.
     *
     * A certificate is considered self-signed if the issuer and subject
     * distinguished names are equal.
     *
     * @param cert The X509 certificate to check.
     * @return true if the certificate is self-signed, false otherwise.
     */

    public static boolean isSelfSigned(X509Certificate cert) {

        if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                return true;
            }
            return false;
    } 
    
    /**
     * Checks the KeyUsage extension of the given X509 certificate.
     * 
     * The method prints the value of each key usage flag, or an error message if
     * the extension is not present or if an error occurs during the check.
     * 
     * @param cert The X509 certificate to check.
     */
     public static void checkKeyUsage(X509Certificate cert) {
       
            boolean[] keyUsage = cert.getKeyUsage();

            if (keyUsage == null) {
                System.out.println("Aucune extension KeyUsage trouvée.");
                return;
            }
            System.out.println("KeyUsage :");
            if (keyUsage[0]) System.out.println("- Digital Signature : true");
            if (keyUsage[1]) System.out.println("- Non-Repudiation   : true");
            if (keyUsage[2]) System.out.println("- Key Encipherment  : true");
            if (keyUsage[3]) System.out.println("- Data Encipherment : true");
            if (keyUsage[4]) System.out.println("- Key Agreement     : true");
            if (keyUsage[5]) System.out.println("- Key Cert Sign     : true");
            if (keyUsage[6]) System.out.println("- CRL Sign          : true");
            if (keyUsage[7]) System.out.println("- Encipher Only     : true");
            if (keyUsage[8]) System.out.println("- Decipher Only     : true");
    }   

    /**
     * Checks the validity period of the given X509 certificate.
     * 
     * The method prints a message indicating whether the certificate is not yet
     * valid, has expired, or is currently valid.
     * 
     * @param cert The X509 certificate to check.
     */
    public static void checkValidityPeriod(X509Certificate cert) {
       
            Date currentDate = new Date();
            if (currentDate.before(cert.getNotBefore())) {
                System.out.println("Le certificat n'est pas encore valide.");
            } else if (currentDate.after(cert.getNotAfter())) {
                System.out.println("Le certificat a expiré.");
            } else {
                System.out.println("Le certificat est valide ");
            }
    }

    public static void checkSignatureAPICrypto(X509Certificate cert,PublicKey publicKey,String signatureAlgorithm,byte[] signature){
        try{
            Signature signatureVerifier = Signature.getInstance(signatureAlgorithm);
            signatureVerifier.initVerify(publicKey);
            signatureVerifier.update(cert.getEncoded());
            if (signatureVerifier.verify(signature)) {
                System.out.println("La signature est valide");
            } else {
                System.out.println("La signature est invalide");
            }
        }
        catch (Exception e){
            System.out.println("Erreur lors de la mise à jour de la signature : " + e.getMessage());
        }
    }
}
