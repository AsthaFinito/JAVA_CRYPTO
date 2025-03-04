# 🛡️ JAVA_CRYPTO  
**Projet de cryptographie en Java – Semestre 8**  

🔐 Implémentation de fonctionnalités de cryptographie en Java, incluant la gestion des certificats, la vérification de signatures et la gestion des CRL/OCSP.

---

## 📥 Installation  

### ✅ **Prérequis** 
- **Java 17+** 

### 📌 **Étapes d’installation**  
1. **Cloner le projet**  
   ```sh
   git clone https://github.com/AsthaFinito/JAVA_CRYPTO.git
   cd JAVA_CRYPTO
2. **Compilation / Run** 
   ```sh
   java src/main/java/ValidateCertChain.java -format <DER|PEM> <MyCARootPath>
   java -cp "bcprov-jdk18on-1.80.jar;bcpkix-jdk18on-1.80.jar;bcutil-jdk18on-1.80.jar;lib/*" src/main/java/ValidateCertChain.java -format <DER|PEM> <MyCARootPath> <MyCAIntermediatePath> <...> <MyCALeafPath>

### 📑 Réponses à l'énoncé ###

1. **ValidCertificate.java**

      Contient les réponses pour l'exercices 3.1
2. **ValidCertificateChain.java**

      Contient les réponses pour l'exercices 3.2 et 3.3
      
Vous pouvez utiliser le format \<QUESTION X.Y.Z\> pour naviguer plus facilement dans le code via le ctrl+f

