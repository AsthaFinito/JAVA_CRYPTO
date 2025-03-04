import java.io.File;
import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;


public class ValidCertificate {
    public static void main(String[] args) {
        if(!processArguments(args)){ //QUESTION 3.1.1
            System.out.println("processArguments : FAILED");
            return;
        }
        else{
            System.out.println("processArguments : PASS");
        }
        if(!processVerif(args)){
            System.out.println("processVerif : FAILED");
            return;
        }
        else{
            System.out.println("processVerif : PASS");
            System.out.println("le certificat est un certificat root completement valide");
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

    public static boolean processArguments(String[] args) {//QUESTION 3.1.1
        
        if (args.length != 3) {
            System.out.println("Format à respecter : -format <DER|PEM> <NameFile>");
            return false;
        }
        
        // System.out.println("Arguments: " + Arrays.toString(args));
        
        if ((!args[0].equals("-format")) || (!args[1].equals("DER") && !args[1].equals("PEM"))) {
            System.out.println("Erreur : First flag incorrect");
            return false;
        }
        
        File certFile = new File(args[2]);
        if (!certFile.exists() || !certFile.isFile() || (!certFile.getName().toLowerCase().endsWith("der") && !certFile.getName().toLowerCase().endsWith("pem"))) {
            System.out.println("Erreur : Le fichier spécifié n'existe pas ou n'est pas un fichier valide.");
            return false;
        }
        if((args[1].equals("DER") && !certFile.getName().toLowerCase().endsWith("der")) || (args[1].equals("PEM") && !certFile.getName().toLowerCase().endsWith("pem"))){
            System.out.println("Erreur : Le fichier spécifié ne correspond pas a celui au flag -format");
            return false;
        }
        return true;
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

    public static boolean isSelfSigned(X509Certificate cert) {//QUESTION 3.1.2
        try {
            if (!cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                System.out.println("le certificat n'est pas auto-signé");
                return false;
            }
            PublicKey publicKey = cert.getPublicKey();
            cert.verify(publicKey);
            return true;
        } catch (Exception e) {
            System.out.println("la signature n'est pas la bonne");
            return false;
        }
    } 
    
    /**
     * Checks the KeyUsage extension of the given X509 certificate.
     * 
     * The method prints the value of each key usage flag, or an error message if
     * the extension is not present or if an error occurs during the check.
     * 
     * @param cert The X509 certificate to check.
     */
     public static boolean checkKeyUsage(X509Certificate cert) {//QUESTION 3.1.4
       
            boolean[] keyUsage = cert.getKeyUsage();

            // System.out.println("KeyUsage :");
            // if (keyUsage[0]) System.out.println("- Digital Signature : true");
            // if (keyUsage[1]) System.out.println("- Non-Repudiation   : true");
            // if (keyUsage[2]) System.out.println("- Key Encipherment  : true");
            // if (keyUsage[3]) System.out.println("- Data Encipherment : true");
            // if (keyUsage[4]) System.out.println("- Key Agreement     : true");
            // if (keyUsage[5]) System.out.println("- Key Cert Sign     : true");
            // if (keyUsage[6]) System.out.println("- CRL Sign          : true");
            // if (keyUsage[7]) System.out.println("- Encipher Only     : true");
            // if (keyUsage[8]) System.out.println("- Decipher Only     : true");
            if (keyUsage == null || keyUsage.length < 6 || !keyUsage[5] || !keyUsage[6]) {
                System.out.println("Erreur : Key usage incorrecte pour un certificat root");
                return false;
            }
            return true;
    }   

    /**
     * Checks the validity period of the given X509 certificate.
     * 
     * The method prints a message indicating whether the certificate is not yet
     * valid, has expired, or is currently valid.
     * 
     * @param cert The X509 certificate to check.
     */
    public static boolean checkValidityPeriod(X509Certificate cert) {//QUESTION 3.1.5
       
            Date currentDate = new Date();
            if (currentDate.before(cert.getNotBefore())) {
                System.out.println("Le certificat n'est pas encore valide");
                return false;
            } else if (currentDate.after(cert.getNotAfter())) {
                System.out.println("Le certificat a expiré.");
                return false;
            }
            return true;
    }

    /**
     * Checks the signature of the given X509 certificate using the given public
     * key and signature algorithm.
     * 
     * The method prints a message indicating whether the signature is valid or
     * not.
     * 
     * @param cert The X509 certificate to check.
     * @param publicKey The public key to use when verifying the signature.
     * @param signatureAlgorithm The algorithm to use when verifying the
     *            signature.
     * @param signature The signature to verify.
     */
    public static boolean checkSignatureAPICrypto(X509Certificate cert,PublicKey publicKey,String signatureAlgorithm,byte[] signature){//QUESTION 3.1.6
        try{
            Signature signatureVerifier = Signature.getInstance(signatureAlgorithm);
            signatureVerifier.initVerify(publicKey);
            signatureVerifier.update(cert.getTBSCertificate());
            if (!signatureVerifier.verify(signature)) {
                System.out.println("La signature est invalide");
                return false;
            }
        }
        catch (Exception e){
            System.out.println("Erreur lors de la mise à jour de la signature : " + e.getMessage());
        }
        return true;
    }

    /**
     * Processes the verification of a certificate from a given file.
     * 
     * Prints information about the certificate, including its serial number, public
     * key, signature algorithm, subject, issuer, key usage, validity period, and
     * signature verification result.
     * 
     * @param args The command line arguments, where args[0] is the command name, and
     *            args[2] is the path to the certificate file to verify.
     */
    public static boolean processVerif(String[] args) {    
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(args[2]);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();
            // System.out.println("Numéro de série : " + cert.getSerialNumber());
            PublicKey publicKey = cert.getPublicKey();
            // System.out.println("Clé publique : " + publicKey);
            // System.out.println("Algo : " + cert.getSigAlgName());
            if (!isSelfSigned(cert)) {//QUESTION 3.1.2
                System.out.println("Erreur : NOT SELF_SIGNED OR BAD SIGNATURE (ce code ne fonctionne que pour les self-signed certificates)");       
                return false;
            }
            System.out.println("Sujet : " + cert.getSubjectX500Principal());//QUESTION 3.1.3
            System.out.println("Émetteur : " + cert.getIssuerX500Principal());//QUESTION 3.1.3
            if(!checkKeyUsage(cert)){//QUESTION 3.1.4
                System.out.println("Erreur : BAD KEY USAGE ");       
                return false;
            }
            if(!checkValidityPeriod(cert)){//QUESTION 3.1.5
                System.out.println("Erreur : BAD Validity Period ");       
                return false;
            }
            if(!checkSignatureAPICrypto(cert,publicKey,cert.getSigAlgName(),cert.getSignature())){//QUESTION 3.1.6
                System.out.println("Erreur : BAD SIGNATURE ");       
                return false;
            }
        } catch (Exception e) {
            System.err.println("Erreur lors de la lecture du certificat : " + e.getMessage());
        }   
        return true;  
    }
}