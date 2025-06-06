import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;


public class ValidateCertChain {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args) {
        if(processArguments(args)){//QUESTION 3.2.1
            System.out.println("processArguments PASS");
            X509Certificate[] certChain = loadCertificates(args);
            if(!validateCertificateChain(certChain)){//Question 3.2.1
                System.out.println("validateCertificateChain FAILED");
                return;
            }
            else{
                System.out.println("validateCertificateChain PASS");
            }
            //System.out.println(verifySignatureBigInteger(certChain));
            if(!verifySignatureBigInteger(certChain)){//QUESTION 3.2.2 / QUESTION 3.2.3
                System.out.println("verifySignatureBigInteger FAILED");
                return;
            }
            else{
                System.out.println("verifySignatureBigInteger PASS"); 
            }
            if(!verifyKeyUsage(certChain)){//QUESTION 3.2.4
                System.out.println("verifyKeyUsage FAILED");
                return;
            }
            else{
                System.out.println("verifyKeyUsage PASS");
            }
            if(!verifyBasicConstraints(certChain)){//QUESTION 3.2.5
                System.out.println("verifyBasicConstraints FAILED");
                return;
            }
            else{
                System.out.println("verifyBasicConstraints PASS");
            }
            if(!verifyRevocateStatus(certChain)){//QUESTION 3.3.1 / /QUESTION 3.3.2 / QUESTION 3.3.3
                System.out.println("verifyRevocateStatus FAILED");
            }
            else{
                System.out.println("verifyRevocateStatus PASS");
            }
            System.out.println("Chaine de certificat complement valide");
        }
        else{
           System.out.println("processArguments FAILED");
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
            public static boolean processArguments(String[] args) {//QUESTION 3.2.1
                try{
                if (args.length < 3) {
                    System.out.println("Format à respecter : -format <DER|PEM> <NameFileRCA> <NameFileICA> <...> <NameFileLCA>");
                    return false;
                }
        
                if ((!args[0].equals("-format")) || (!args[1].equals("DER") && !args[1].equals("PEM"))) {
                    System.out.println("Erreur : First flag incorrect");
                    return false;
                }
                
                int numFiles = args.length - 2;
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
                        return false;
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
                        certChain[i - 2] = cert; 
                    }
                    //System.out.println("Tableau de certificats chargé.");
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
        //System.out.println("Signature de la chaine de certificats valide.");
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

        /**
         * Verifies the signature of each certificate in the provided certificate chain, using either RSA or ECDSA
         * algorithms. The hash function used for the signature is determined by the algorithm name of the first
         * certificate in the chain.
         * 
         * @param certChain The array of X509 certificates to verify.
         * @return true if the signatures are valid, false otherwise.
         */
    public static boolean verifySignatureBigInteger(X509Certificate[] certChain) {//QUESTION 3.2.2 / QUESTION 3.2.3
        // System.out.println(certChain[0].getSigAlgName());
        String hashFunction = certChain[0].getSigAlgName().split("with")[0];
        if (certChain[0].getSigAlgName().contains("RSA")){//Question 3.2.2
            // System.out.println("Checking RSA signature");
           

           // System.out.println("Fonction de hachage utilisée : " + hashFunction);
            if(!verifySignatureRSABigInteger(certChain,hashFunction)){
                System.out.println("signature rsa non valide");
                return false;
            }
            return true;
        }
        else if(certChain[0].getSigAlgName().contains("ECDSA")){//Question 3.2.3
           
            if(!verifySignatureECDSABigInteger(certChain,hashFunction)){
                return false;
            }
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

    public static boolean verifySignatureRSABigInteger(X509Certificate[] certChain,String hashFunction) {
        try {
            for (int i = 0; i < certChain.length; i++) {
                X509Certificate currentCert = certChain[i];
               //ROOT
                if (i == 0) {
                    RSAPublicKey publicKey = (RSAPublicKey) currentCert.getPublicKey();
                    //System.out.println(currentCert.getSigAlgName());
                    MessageDigest md = MessageDigest.getInstance(hashFunction);
                    byte[] hash = md.digest(currentCert.getTBSCertificate());

                    BigInteger signature = new BigInteger(1, currentCert.getSignature());
                    BigInteger result = signature.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
                    if (!result.toString(16).contains(new BigInteger(1, hash).toString(16))) {
                        System.out.println("CA ROOT INVALID SIGNATURE");
                        return false;
                    }
                }    
                else{
                    RSAPublicKey publicKey = (RSAPublicKey) certChain[i - 1].getPublicKey();//clé n-1
                    // System.out.println("pubKey : "+certChain[i - 1].getPublicKey());
                    // System.out.println("pubKeyRSA : "+publicKey);
                    MessageDigest md = MessageDigest.getInstance(hashFunction);
                    byte[] hash = md.digest(currentCert.getTBSCertificate()); //HASH(msg)
                    // System.out.println("hash lengt : "+hash);
                    // System.out.println("getPublicExponent : "+publicKey.getPublicExponent());
                    // System.out.println("module : " +publicKey.getModulus().bitLength());
                    //String signatureHex = String.format("%040x", new BigInteger(1, signature2));
                    // System.out.println("signature récup via le getSignature (hex) : " +signatureHex.length());
                    BigInteger signature = new BigInteger(currentCert.getSignature());
                    //System.out.println("signature (hex) lenght : " + result.bitLength());
                    BigInteger result = signature.modPow(publicKey.getPublicExponent(), publicKey.getModulus());//h'
                    // System.out.println("Result (hex) lenght : " + result.toString(16));//.indexOf("3031"));
                    // System.out.println("Result hash : " + new BigInteger(1, hash).toString(16));
                    // System.out.println("getPublicExponent + getModulus : " +publicKey.getPublicExponent().bitLength()+" "+ publicKey.getModulus().bitLength());
                    

                    
                    if (!result.toString(16).contains(new BigInteger(1, hash).toString(16))) {
                        System.out.println("CA"+certChain[i].getSubjectX500Principal().getName()+" INVALID SIGNATURE");                 
                        return false;
                    } 
                }
                
            }
        
        } catch (Exception e) {
            System.out.println("Erreur de signature RSA BIG INTEGER: " + e.getMessage());
        }
        
        return true;
    }



    /**
     * Extracts the curve name from an EC public key string in the format:
     * "EC Public Key [curveName: ...]".
     * 
     * @param ecPublicKeyString The EC public key string.
     * @return The extracted curve name, or null if not found.
     */
    public static String getCurveName(String ecPublicKeyString) {
        int startIndex = ecPublicKeyString.indexOf(": ") + ": ".length();
        int endIndex = ecPublicKeyString.indexOf(" [", startIndex);
        if (startIndex >= 0 && endIndex >= 0) {
            return ecPublicKeyString.substring(startIndex-1, endIndex);
        } else {
            return null; 
        }
    }
    /**
     * Extracts the public point from an EC public key.
     * 
     * @param ecPublicKey The EC public key.
     * @return The extracted public point.
     */
    private static ECPoint[] extractPublicKeyBC(ECPublicKey ecPublicKey) {
        BigInteger x = ecPublicKey.getW().getAffineX();
        BigInteger y = ecPublicKey.getW().getAffineY();
        // System.out.println("ecPublicKey : "+ecPublicKey.getParams());
        // System.out.println("ecPublicKey : "+getCurveName(ecPublicKey.getParams().toString()));
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(getCurveName(ecPublicKey.getParams().toString()));
        // System.out.println("ecSpec.getG() "+ecSpec.getG());
        
        return new ECPoint[]{ecSpec.getCurve().createPoint(x, y), ecSpec.getG()};
    }

    /**
     * Extracts the two components (r and s) from an ECDSA signature byte array.
     * 
     * @param signature The ECDSA signature byte array.
     * @return An array of two BigIntegers, r and s, the components of the signature.
     * @throws IOException If there is a problem parsing the signature.
     */
    private static BigInteger[] extractRandS(byte[] signature) throws IOException {
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(signature)) {
        DLSequence seq = (DLSequence) asn1InputStream.readObject();
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
       
        // System.out.println("r2: " +r2.bitLength());
        // System.out.println("s2 " + s2.bitLength());
        // System.out.println("rBytes: " +rBytes.length);
        // System.out.println("sBytes " + sBytes.length);
        // System.out.println("r: " +r.bitLength());
        // System.out.println("s " + s.bitLength());
     
        return new BigInteger[]{r, s};
    }
}

    
    
    /**
     * Verifies the ECDSA signature of each certificate in the chain using the
     * public key of the previous certificate, and by checking that the subject
     * of each certificate matches the issuer of the previous certificate.
     * 
     * @param certChain The array of X509 certificates to validate.
     * @param hashFunction The hash function name used for the signature [BUGGED]
     * @return true if the certificate chain is valid, false otherwise.
     */
    public static boolean verifySignatureECDSABigInteger(X509Certificate[] certChain,String hashFunction){//QUESTION 3.2.3
        try {
            for (int i = 0; i < certChain.length; i++) {
                X509Certificate currentCert = certChain[i];
                if(i==0){
                    // System.out.println("SKIP");
                    ECPublicKey ecPublicKey = (ECPublicKey) certChain[i].getPublicKey();
                    String hashFunction2 = certChain[i].getSigAlgName().split("with")[0];
                    MessageDigest md = MessageDigest.getInstance(hashFunction2);
                    byte[] hash = md.digest(currentCert.getTBSCertificate());
                    ECPoint[] points = extractPublicKeyBC(ecPublicKey);
                    ECPoint Q = points[0]; 
                    ECPoint G = points[1];
                    BigInteger[] rs = extractRandS(certChain[i].getSignature());
                    BigInteger r = rs[0];
                    BigInteger s = rs[1];
                    if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(ecPublicKey.getParams().getOrder()) >= 0) {
                        System.out.println("Erreur : La valeur de r est invalide.");
                        return false;
                    }
                    
                    if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(ecPublicKey.getParams().getOrder()) >= 0) {
                        System.out.println("Erreur : La valeur de s est invalide.");
                        return false;
                    }                    
                    BigInteger w = s.modInverse(ecPublicKey.getParams().getOrder());
                    BigInteger e = new BigInteger(1, hash);
                    BigInteger u1 = e.multiply(w).mod(ecPublicKey.getParams().getOrder());
                    BigInteger u2 = r.multiply(w).mod(ecPublicKey.getParams().getOrder());
                    ECPoint u1G = G.multiply(u1).normalize();
                    ECPoint u2Q = Q.multiply(u2).normalize();
                    ECPoint P = u1G.add(u2Q).normalize();
                    if (P.isInfinity()) {
                        throw new IllegalStateException("Le point P est à l'infini, impossible d'obtenir la coordonnée X.");
                    }
                    BigInteger xP = P.getAffineXCoord().toBigInteger().mod(ecPublicKey.getParams().getOrder());
                    if (!xP.equals(r)) {
                        System.out.println("CA ROOT INVALID SIGNATURE");
                        return false;
                    }
                }
                else{
               
                    String hashFunction2 = certChain[i].getSigAlgName().split("with")[0];
                    // System.out.println(hashFunction2);
                    MessageDigest md = MessageDigest.getInstance(hashFunction2);
                    byte[] hash = md.digest(currentCert.getTBSCertificate());

                    ECPublicKey ecPublicKey = (ECPublicKey) certChain[i-1].getPublicKey();
                   // System.out.println("ecPublicKey : "+ecPublicKey.getParams());
                    ECPoint[] points = extractPublicKeyBC(ecPublicKey);//Obtenir Q en ECPoint BOUNCYCASTLE
                    //System.out.println("bcPoint : "+bcPoint);
                    ECPoint Q = points[0]; 
                    ECPoint G = points[1];
                    //ECPoint N = points[2];
                    BigInteger[] rs = extractRandS(certChain[i].getSignature());
                    BigInteger r = rs[0];
                    BigInteger s = rs[1];
                    // System.out.println("r : "+r+" "+r.bitLength());
                    // System.out.println("s : "+s+" "+s.bitLength());
                    // System.out.println("n : "+ecPublicKey.getParams().getOrder()+" "+ecPublicKey.getParams().getOrder().bitLength());
                    if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(ecPublicKey.getParams().getOrder()) >= 0) {
                        System.out.println("Erreur : La valeur de r est invalide");
                        return false;
                    }
                    
                    if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(ecPublicKey.getParams().getOrder()) >= 0) {
                        System.out.println("Erreur : La valeur de s est invalide");
                        return false;
                    }
                    
                    BigInteger w = s.modInverse(ecPublicKey.getParams().getOrder());
                    // System.out.println("w : "+w+" "+w.bitLength());
                    BigInteger e = new BigInteger(1, hash);
                    BigInteger u1 = e.multiply(w).mod(ecPublicKey.getParams().getOrder());
                    BigInteger u2 = r.multiply(w).mod(ecPublicKey.getParams().getOrder());
                    // System.out.println("u1 : " + u1.toString(16));
                    // System.out.println("u2 : " + u2.toString(16));
                    // System.out.println("G : " + G);
                    // System.out.println("Q : " + Q);             
                    ECPoint u1G = G.multiply(u1).normalize();
                    ECPoint u2Q = Q.multiply(u2).normalize();
                    // System.out.println("u1G : " + u1G);
                    // System.out.println("u2Q : " + u2Q);
                    ECPoint P = u1G.add(u2Q).normalize();
                    // System.out.println("P : " + P);
                    if (P.isInfinity()) {
                        throw new IllegalStateException("Le point P est à l'infini, impossible d'obtenir la coordonnée X.");
                    }
                    // System.out.println("x : " + P.getAffineXCoord().toBigInteger().toString(16)); // Affiche en hexadécimal
                    // System.out.println("y : " + P.getAffineYCoord().toBigInteger().toString(16));
                    BigInteger xP = P.getAffineXCoord().toBigInteger().mod(ecPublicKey.getParams().getOrder());
                    // System.out.println("xP: "+xP +" "+xP.bitLength());
                    
                    if (!xP.equals(r)) {
                        System.out.println("CA"+certChain[i].getSubjectX500Principal().getName()+" INVALID SIGNATURE");       
                        return false;
                    }
                    
                }
            }
        }
        catch (Exception e) {
            System.out.println("Erreur de signature ECDSA BIG INTEGER: " + e.getMessage());
        }
        return true;
    }


    /**
     * Verifies the keyUsage extension of each certificate in the chain.
     * 
     * The method prints an error message if the extension is not present or if
     * an error occurs during the check.
     * 
     * @param certChain The array of X509 certificates to validate.
     * @return true if the keyUsage of the certificate chain is valid, false
     *         otherwise.
     */
    public static boolean verifyKeyUsage(X509Certificate[] certChain){
        int LEVEL_CA=2;//0 -> root , 1 -> inter , 2-> leaf
        try {
            for (int i = 0; i < certChain.length; i++) {
                if(i==0){
                    LEVEL_CA=0;
                }
                else if(i==certChain.length-1){
                    LEVEL_CA=2;
                }
                else{
                    LEVEL_CA=1;
                }
                boolean[] keyUsage = certChain[i].getKeyUsage();
                // System.out.println(i);
                // if (keyUsage[0]) System.out.println("- Digital Signature : true");
                // if (keyUsage[1]) System.out.println("- Non-Repudiation   : true");
                // if (keyUsage[2]) System.out.println("- Key Encipherment  : true");
                // if (keyUsage[3]) System.out.println("- Data Encipherment : true");
                // if (keyUsage[4]) System.out.println("- Key Agreement     : true");
                // if (keyUsage[5]) System.out.println("- Key Cert Sign     : true");
                // if (keyUsage[6]) System.out.println("- CRL Sign          : true");
                // if (keyUsage[7]) System.out.println("- Encipher Only     : true");
                // if (keyUsage[8]) System.out.println("- Decipher Only     : true");

                // MAP KEY USAGE
                // keyUsage[0] = Digital Signature
                // keyUsage[1] = Non Repudiation
                // keyUsage[2] = Key Encipherment
                // keyUsage[3] = Data Encipherment -> SI RSA
                // keyUsage[4] = Key Agreement -> SI EC
                // keyUsage[5] = Key Cert Sign 
                // keyUsage[6] = CRL Sign
                // keyUsage[7] = Encipher Only
                // keyUsage[8] = Decipher Only
                switch (LEVEL_CA) {
                    case 0: // ROOT CA
                        if (keyUsage == null || keyUsage.length < 6 || !keyUsage[5] || !keyUsage[6]) {
                            System.out.println("Erreur : Key usage incorrecte sur le certificat root");
                            return false;
                        }
                        break;
                
                    case 1: // INTERMEDIATE CA
                        if (!keyUsage[0]|| !keyUsage[5] || !keyUsage[6]) {
                            System.out.println("Erreur : Key usage incorrecte sur les CA intermédiaires");
                            return false;
                        }
                        break;
                
                    case 2: // LEAF CA
                        if (keyUsage == null || keyUsage.length < 6 || !keyUsage[0]) {
                            System.out.println("Erreur : Key usage incorrecte sur les leaf CA");
                            return false;
                        }
                        break;
                
                    default:
                        System.out.println("Erreur : Niveau de certificat inconnu.");
                        return false;
                }
                
            }
            
        } catch (Exception e) {
            System.out.println("Erreur de verification key usage: " + e.getMessage());
        }

        return true;
    }

    /**
     * Verifies the basic constraints of a certificate chain.
     * 
     * This method takes an array of X509 certificates as argument and checks
     * the basic constraints of each certificate. The method checks the path
     * length constraint of each certificate and verifies that the root
     * certificate has a path length constraint of 0 or -1, the leaf
     * certificates have a path length constraint of -1, and the intermediate
     * certificates have a path length constraint of 0.
     * 
     * @param certChain The array of X509 certificates to verify.
     * @return true if the certificate chain is valid, false otherwise.
     */
    public static boolean verifyBasicConstraints(X509Certificate[] certChain){//QUESTION 3.2.5
        // certChain[i].getExtensionValue()
        try {
            for (int i = 0; i < certChain.length; i++) {
                int pathLen = certChain[i].getBasicConstraints();
                //System.out.println(certChain[i]);
                if((pathLen==0 || pathLen==-1) && i==0){
                    System.out.println("Erreur sur la verif des contraints du root");
                    return false;
                }
                else if((i==certChain.length-1)&& pathLen!=-1){
                    System.out.println("Erreur sur la verif des contraints des leafs");
                    return false;
                }
                else if((i==certChain.length-2)&& pathLen!=-0){
                    System.out.println("Erreur sur la verif des contraints des CA lenght-1");
                    return false;
                }
                // else if((i!=0 || i!=certChain.length-1 ||i!=certChain.length-2)&& (pathLen==0 || pathLen==-1)){
                //     System.out.println("Erreur sur la verif des contraints des CA intermediares (+de 3 CA CHAIn)");
                //     return false;
                // }

            }


        } catch (Exception e) {
            System.out.println("Erreur de verifyBasicConstraints: " + e.getMessage());
        }
        return true;
    }

    /**
     * Extracts the CRL distribution point URL from the given extension value.
     * 
     * @param extensionValue The value of the extension to extract the CRL distribution point URL from.
     * @return The CRL distribution point URL if found, null otherwise.
     * @throws Exception If an error occurs while parsing the extension value.
     */
    private static String extractCrlUrlFromExtension(byte[] extensionValue) throws Exception {

        try (ASN1InputStream asn1InputStream = new ASN1InputStream(extensionValue)) {
            ASN1OctetString asn1OctetString = (ASN1OctetString) asn1InputStream.readObject();

            try (ASN1InputStream asn1InputStream2 = new ASN1InputStream(asn1OctetString.getOctets())) {
                ASN1Sequence asn1Sequence = (ASN1Sequence) asn1InputStream2.readObject();

                CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(asn1Sequence);

                for (DistributionPoint distributionPoint : crlDistPoint.getDistributionPoints()) {
                    DistributionPointName dpn = distributionPoint.getDistributionPoint();
                    if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralNames generalNames = GeneralNames.getInstance(dpn.getName());
                        for (GeneralName generalName : generalNames.getNames()) {
                            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                DERIA5String uri = (DERIA5String) DERIA5String.getInstance(generalName.getName());
                                return uri.getString();
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
/**
 * Loads a CRL (Certificate Revocation List) from the specified file.
 * 
 * This method attempts to read and generate an X509CRL object from the given file,
 * which is expected to contain a CRL in X.509 format.
 * 
 * @param crlFile The file containing the CRL to be loaded.
 * @return An X509CRL object if the CRL is successfully loaded, null otherwise.
 */

    private static X509CRL loadCRLFromFile(File crlFile) {
        try (InputStream fis = new FileInputStream(crlFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(fis);
        } catch (Exception e) {
            System.err.println("Erreur lors du chargement de la CRL en cache : " + e.getMessage());
            return null;
        }
    }
/**
 * Downloads a Certificate Revocation List (CRL) from the specified URL.
 * 
 * This method attempts to download a CRL from the provided URL and cache it
 * locally in the './src/certificats/crlList/' directory using the host name
 * as the file name. If a valid cached CRL already exists, it will be used
 * instead of downloading a new one. The method returns an X509CRL object 
 * representing the CRL.
 * 
 * @param crlUrl The URL from which to download the CRL.
 * @return An X509CRL object if the CRL is successfully downloaded or loaded
 *         from cache.
 * @throws Exception If an error occurs during the download or processing of
 *         the CRL.
 */

    public static X509CRL downloadCRL(String crlUrl) throws Exception {
        // System.out.println("Téléchargement de la CRL depuis : " + crlUrl);
        URI url = new URI(crlUrl);
        String buildCrlFilePath = "./src/certificats/crlList/"+url.getHost()+".crl";
        File crlFile = new File(buildCrlFilePath);
        if (crlFile.exists()) {
            X509CRL cachedCRL = loadCRLFromFile(crlFile);
            if (cachedCRL != null && (cachedCRL.getNextUpdate() == null || !cachedCRL.getNextUpdate().before(new Date()))) {//QUESTION 3.3.1
                System.out.println("Utilisation de la CRL en cache : " + buildCrlFilePath);
                return cachedCRL;
            }
        }
       // Path crlFilePath = Paths.get(buildCrlFilePath);
        try (InputStream crlStream = url.toURL().openStream()) {//QUESTION 3.3.1
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
            // System.out.println("CRL téléchargée avec succès !");
            FileOutputStream fos = new FileOutputStream(buildCrlFilePath);
            fos.write(crl.getEncoded());
            fos.close();
            return crl;
        }
    }
    
    /**
     * Extracts the OCSP URL from the given certificate's Authority Information Access extension.
     * 
     * @param certificate The certificate to extract the OCSP URL from.
     * @return The OCSP URL if found, null otherwise.
     * @throws Exception If an error occurs while parsing the extension value.
     */
    public static String getOCSPUrl(X509Certificate certificate) throws Exception {
        byte[] aiaExtensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        
        if (aiaExtensionValue == null) {
            throw new Exception("Le certificat ne contient pas d'extension Authority Information Access.");
        }
        ASN1InputStream asn1InputStream = new ASN1InputStream(aiaExtensionValue);
        ASN1Primitive derObject = asn1InputStream.readObject();
        asn1InputStream.close();
        ASN1OctetString octetString = ASN1OctetString.getInstance(derObject);
        ASN1Primitive aiaPrimitive = ASN1Primitive.fromByteArray(octetString.getOctets());
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaPrimitive);
        for (AccessDescription ad : aia.getAccessDescriptions()) {
            if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                GeneralName gn = ad.getAccessLocation();
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    ASN1Encodable encodable = gn.getName();
                    String ocspUrl = DERIA5String.getInstance(encodable).getString();
                    return ocspUrl;
                }
            }
        }
        throw new Exception("Aucune URL OCSP trouvée dans le certificat.");
    }
    
    /**
     * Creates an OCSP request for the given certificate and issuer certificate.
     * 
     * @param cert The certificate to request the revocation status for.
     * @param issuerCert The issuer of the certificate.
     * @return The OCSP request as a byte array.
     * @throws Exception If an error occurs while creating the OCSP request.
     */
    private static byte[] createOCSPRequest(X509Certificate cert, X509Certificate issuerCert){
        byte[] return_value = null;
        try {
                
                CertificateID certId = new CertificateID(
                new BcDigestCalculatorProvider().get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-1")),
                new JcaX509CertificateHolder(issuerCert),
                cert.getSerialNumber());
                OCSPReqBuilder builder = new OCSPReqBuilder();
                builder.addRequest(certId);
                OCSPReq ocspRequest = builder.build();
                return_value=ocspRequest.getEncoded();
            
        } catch (Exception e) {
            System.out.println("Erreur de createOCSPRequest " + e.getMessage());
        }
        return return_value;
    }

/**
 * Sends an OCSP request to the specified OCSP responder URL and returns the response.
 *
 * @param ocspUrl The URL of the OCSP responder to send the request to.
 * @param ocspRequest The OCSP request as a byte array.
 * @return The OCSP response as a byte array if the request is successful, or null if an error occurs.
 * @throws Exception If an error occurs while creating the connection or sending the request.
 */

    public static byte[] sendOCSPRequest(String ocspUrl, byte[] ocspRequest) {
        try {
            URI url = new URI(ocspUrl);
            URL url2 = url.toURL();
            HttpURLConnection connection = (HttpURLConnection) url2.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/ocsp-request");
            connection.setRequestProperty("Accept", "application/ocsp-response");
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(ocspRequest);
            }
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return connection.getInputStream().readAllBytes();
            } else {
                System.err.println("Erreur lors de l'envoi de la requête OCSP : " + responseCode);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifyRevocateStatus(X509Certificate[] certChain){//QUESTION 3.3.1 / /QUESTION 3.3.2 / QUESTION 3.3.3
        try {
            for (int i = 0; i < certChain.length; i++) {
                if(i==0){
                    System.out.println("SKIP ");
                }
                else{
                    // System.out.println(getOCSPUrl(certChain[i]));
                    byte[] crl_sequence_byte = certChain[i].getExtensionValue("2.5.29.31");
                    // System.out.println("Valeur de l'extension CRL Distribution Points (hex) : " + hexValue);
                    String crlUrl = extractCrlUrlFromExtension(crl_sequence_byte);
                    // System.out.println("URL de la CRL : " + crlUrl);
                    X509CRL cr = downloadCRL(crlUrl);//QUESTION 3.3.1 / //QUESTION 3.3.3
                    if(cr.isRevoked(certChain[i])){
                        System.out.println("Erreur : Certificat révoqué");
                        return false;
                    }
                    //END P1
                    byte[] byte_request=createOCSPRequest(certChain[i],certChain[i-1]);//QUESTION 3.3.2
                    byte[] ocspResponseByte =sendOCSPRequest(getOCSPUrl(certChain[i]),byte_request);
                    if (ocspResponseByte != null ) {
                       OCSPResp ocspResponse = new OCSPResp(ocspResponseByte);
                       if (ocspResponse.getStatus() == OCSPResp.SUCCESSFUL) {
                        // System.out.println("Reponse succesful");
                        BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                        // System.out.println(basicResponse);
                        SingleResp[] responses = basicResponse.getResponses();
                        // System.out.println("Nombre de réponses : " + responses.length);
                        if (responses[0].getCertStatus() == CertificateStatus.GOOD) {
                            System.out.println("Statut du certificat : Valide");
                        }
                        else{
                            System.out.println("Statut du certificat : REVOKED");
                            return false;
                        }
                       }
                    } else {
                        System.out.println("Aucune réponse OCSP reçue.");
                        return false;
                    }
                }
                
            }
            
        } catch (Exception e) {
            System.out.println("Erreur de verifyRevocateStatus " + e.getMessage());
        }
        // System.out.println(certChain[1]);
        // System.out.println(certChain[1].getCriticalExtensionOIDs());

        //System.out.println(certChain[1].getVersion());
        return true;
    }
}