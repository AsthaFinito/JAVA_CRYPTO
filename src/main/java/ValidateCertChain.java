import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Set;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ValidateCertChain {
    public static void main(String[] args) {
        if(processArguments(args)){
            Security.addProvider(new BouncyCastleProvider());
            X509Certificate[] certChain = loadCertificates(args);
            if(!validateCertificateChain(certChain)){
                System.out.println("validateCertificateChain failed");
                return;
            }
            else{
                System.out.println("validateCertificateChain passed");
            }
            //System.out.println(verifySignatureBigInteger(certChain));
            if(!verifySignatureBigInteger(certChain)){
                System.out.println("verifySignatureBigInteger failed");
            }
            else{
                System.out.println("verifySignatureBigInteger passed"); 
            }
        }
        
                
        
            }
        /**
         * Retrieves the file extension from a given file name.
         *
         * This method returns the substring of the file name after the last dot ('.').
         * If the file name does not contain a dot, it returns an empty string.
         *
         * @param fileName The name of the file from which to extract the extension.
         * @return The file extension, or an empty string if no extension is found.
         */
        
            private static String getFileExtension(String fileName) {
            int dotIndex = fileName.lastIndexOf('.');
            if (dotIndex == -1) {
                return "";
            }
            return fileName.substring(dotIndex+1);
        }
        /**
         * Processes the command line arguments and checks if they are valid.
         *
         * This method parses the command line arguments and checks if they are valid
         * according to the following rules:
         *  - The first argument must be "-format".
         *  - The second argument must be "DER" or "PEM".
         *  - The third argument must be a file name.
         *  - The file name must have the same extension as the format specified in
         *    the second argument.
         *  - The file must exist and be a regular file.
         *  - The first certificate must be self signed.
         *
         * If any of these rules are not met, the method prints an error message and
         * returns.
         */
            public static boolean processArguments(String[] args) {
                try{
                if (args.length < 3) {
                    System.out.println("Format à respecter : -format <DER|PEM> <NameFileRCA> <NameFileICA> <...> <NameFileLCA>");
                    return false;
                }
        
                if ((!args[0].equals("-format")) || (!args[1].equals("DER") && !args[1].equals("PEM"))) {
                    System.out.println("Erreur : First flag incorrect");
                    return false;
                }
                int numFiles = args.length - 2; // calculate the number of files
                Set<String> certNames = new HashSet<>();
                File[] certFiles = new File[numFiles];
                for (int i = 0; i < numFiles; i++) {
                    certFiles[i] = new File(args[i + 2]);
                    if (!certFiles[i].exists() || !certFiles[i].isFile()) {
                        System.out.println("Erreur : Le fichier spécifié '" + certFiles[i].getPath() + "' n'existe pas ou n'est pas un fichier valide.");
                        return false;
                    }
                    if (!getFileExtension(args[i + 2]).equals((args[1]).toLowerCase())) {
                        System.out.println("Erreur : Le fichier '" + args[i + 2] + "' n'a pas la même extension que le fichier '" + args[1].toLowerCase() + "'.");
                        return false;
                    }
                    if (certNames.contains(args[i + 2])) {
                        System.out.println("Erreur : Le certificat '" + args[i + 2] + "' est déjà présent dans la chaîne de certificats.");
                        return false;
                    }
                    certNames.add(args[i + 2]);
                    
                }
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    FileInputStream fis = new FileInputStream(args[2]);
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
                    fis.close();
                    if(!isSelfSigned(cert)){
                        System.out.println("First certificat invalide (NOT SELF_SIGNED)");
                    }
                return true;
            }
            catch(Exception e){
                System.out.println("Erreur : " + e.getMessage());
                return false;
                 }
            }
            /**
             * Checks whether a given X509 certificate is self-signed or not.
             * 
             * A certificate is self-signed if the issuer and subject principal are the same.
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
             * Loads an array of X509 certificates from the given command line arguments.
             * 
             * The method assumes that the first two arguments are the format and the
             * command name, and that the remaining arguments are the paths to the
             * certificates to load.
             * 
             * The method returns an array of X509 certificates, or null if an error
             * occurs during the loading of the certificates.
             * 
             * @param args The command line arguments.
             * @return An array of X509 certificates, or null if an error occurs.
             */
            public static X509Certificate[] loadCertificates(String[] args){
                try {
                    X509Certificate[] certChain = new X509Certificate[args.length - 2];
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    
                    for (int i = 2; i < args.length; i++) {
                        FileInputStream fis = new FileInputStream(args[i]);
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
                        certChain[i - 2] = cert; // supposons que vous avez une méthode loadCertificate pour charger un certificat à partir d'un fichier
                    }
                    System.out.println("Tableau de certificats chargé.");
                    return certChain;
                    
                } catch (Exception e) {
                    System.out.println("Erreur création du tableau de certificats : " + e.getMessage());
                }
                return null;
                
            }
        
        /**
         * Validates the certificate chain by checking the signature of each certificate
         * in the chain using the public key of the previous certificate, and by
         * checking that the subject of each certificate matches the issuer of the
         * previous certificate.
         * 
         * @param certChain The array of X509 certificates to validate.
         * @return true if the certificate chain is valid, false otherwise.
         */
            public static boolean validateCertificateChain(X509Certificate[] certChain) {
                for (int i = 1; i < certChain.length; i++) {
                    X509Certificate currentCert = certChain[i];
                    X509Certificate nextCert = certChain[i - 1];
                    if (!verifySignature(currentCert, nextCert)) {
                        System.out.println("Erreur de signature dans la chaîne de certificats.");
                        return false;
                    }
                    if (!matchSubjectAndIssuer(currentCert, nextCert)) {
                        System.out.println("Erreur de matchmaking des sujets et des émetteurs.");   
                        return false;
                    }
        }
        System.out.println("Signature de la chaine de certificats valide.");
        return true;
    }

/**
 * Verifies the signature of the current certificate using the public key
 * of the previous certificate in the chain.
 * 
 * This method attempts to verify the signature of the given X509
 * certificate (`currentCert`) against the public key of the
 * previous certificate (`PreviousCertif`). If the verification
 * succeeds without exceptions, it returns true, indicating that the
 * signature is valid. If an exception occurs during verification, it
 * returns false, indicating that the signature is invalid.
 * 
 * @param currentCert The X509 certificate whose signature is to be verified.
 * @param PreviousCertif The X509 certificate containing the public key
 *                       used for verification.
 * @return true if the signature is valid, false otherwise.
 */

    private static boolean verifySignature(X509Certificate currentCert, X509Certificate PreviousCertif) {
    try {
        currentCert.verify(PreviousCertif.getPublicKey());
        return true;
    } catch (Exception e) {
        return false;
    }
}

    /**
     * Verifies that the subject of the previous certificate in the chain matches
     * the issuer of the current certificate. This is a necessary condition for a
     * valid certificate chain.
     * 
     * @param CurrentCertif The current X509 certificate in the chain.
     * @param PreviousCertif The previous X509 certificate in the chain.
     * @return true if the subject of the previous certificate matches the issuer
     *         of the current certificate, false otherwise.
     */
    private static boolean matchSubjectAndIssuer(X509Certificate CurrentCertif, X509Certificate PreviousCertif) {
        if(CurrentCertif.getIssuerX500Principal().equals(PreviousCertif.getSubjectX500Principal())) {
            return true;
        }
        else{
            return false;
        }
    }

    public static boolean verifySignatureBigInteger(X509Certificate[] certChain) {

        if (certChain[0].getSigAlgName().contains("RSA")){
            System.out.println("Checking RSA signature");
            String hashFunction = certChain[0].getSigAlgName().split("with")[0];

           // System.out.println("Fonction de hachage utilisée : " + hashFunction);
            if(!verifySignatureRSABigInteger(certChain,hashFunction)){
                return false;
            }
            return true;
        }
        else if(certChain[0].getSigAlgName().contains("ECDSA")){
            return true;
        }
        else{
            System.out.println("Signature non pris en charge");
            return false;
        }
    }


    


/**
 * Verifies the RSA signature of each certificate in the provided certificate chain.
 *
 * This method iterates through the given array of X509 certificates (`certChain`) and verifies
 * the RSA signature of each certificate using the public key from the previous certificate in
 * the chain. For the root certificate (index 0), the signature is verified against its own
 * public key. The verification process involves computing the hash of the certificate's 
 * TBS (To Be Signed) portion using the specified hash function, and comparing it with the 
 * decrypted signature value. If any signature verification fails, the method prints an 
 * appropriate error message and returns false. If all signatures are verified successfully, 
 * it prints a success message and returns true.
 *
 * @param certChain An array of X509 certificates representing the certificate chain.
 * @param hashFunction The hash function used to compute the hash of the certificate's TBS portion.
 * @return true if all signatures in the certificate chain are valid, false otherwise.
 */

    private static boolean verifySignatureRSABigInteger(X509Certificate[] certChain,String hashFunction) {
        try {
            for (int i = 0; i < certChain.length; i++) {
                X509Certificate currentCert = certChain[i];
               //ROOT
                if (i == 0) {
                    RSAPublicKey publicKey = (RSAPublicKey) currentCert.getPublicKey();
                    //System.out.println(currentCert.getSigAlgName());
                    MessageDigest md = MessageDigest.getInstance(hashFunction);//TODO Every sha
                    byte[] hash = md.digest(currentCert.getTBSCertificate());

                    BigInteger signature = new BigInteger(1, currentCert.getSignature());
                    BigInteger result = signature.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
                    if (!result.toString(16).contains(new BigInteger(1, hash).toString(16))) {
                        return false;
                    }
                }    
                else{
                    RSAPublicKey publicKey = (RSAPublicKey) certChain[i - 1].getPublicKey();//clé n-1
                    // System.out.println("pubKey : "+certChain[i - 1].getPublicKey());
                    // System.out.println("pubKeyRSA : "+publicKey);
                    MessageDigest md = MessageDigest.getInstance("SHA-256");//TODO EVERY SHA 
                    byte[] hash = md.digest(currentCert.getTBSCertificate()); //HASH(msg)
                    // System.out.println("hash lengt : "+hash);
                    // System.out.println("getPublicExponent : "+publicKey.getPublicExponent());
                    // System.out.println("module : " +publicKey.getModulus().bitLength());
                    byte[] signature2 = currentCert.getSignature();
                    //String signatureHex = String.format("%040x", new BigInteger(1, signature2));
                    // System.out.println("signature récup via le getSignature (hex) : " +signatureHex.length());
                    BigInteger signature = new BigInteger(currentCert.getSignature());
                    //System.out.println("signature (hex) lenght : " + result.bitLength());
                    BigInteger result = signature.modPow(publicKey.getPublicExponent(), publicKey.getModulus());//h'
                    // System.out.println("Result (hex) lenght : " + result.toString(16));//.indexOf("3031"));
                    // System.out.println("Result hash : " + new BigInteger(1, hash).toString(16));
                    // System.out.println("getPublicExponent + getModulus : " +publicKey.getPublicExponent().bitLength()+" "+ publicKey.getModulus().bitLength());
                    

                    
                    if (!result.toString(16).contains(new BigInteger(1, hash).toString(16))) {
                        return false;
                    } 
                }
                
            }
        
        } catch (Exception e) {
            System.out.println("Erreur de signature RSA BIG INTEGER: " + e.getMessage());
        }
        
        return true;
    }
}