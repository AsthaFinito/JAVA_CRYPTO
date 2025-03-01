import java.io.File;

public class ValidateCertChain {
    public static void main(String[] args) {
        processArguments(args);

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
    public static void processArguments(String[] args) {
        if (args.length < 3) {
            System.out.println("Format à respecter : -format <DER|PEM> <NameFileRCA> <NameFileICA> <...> <NameFileLCA>");
            return;
        }

        if ((!args[0].equals("-format")) || (!args[1].equals("DER") && !args[1].equals("PEM"))) {
            System.out.println("Erreur : First flag incorrect");
            return;
        }
        int numFiles = args.length - 2; // calculate the number of files
        File[] certFiles = new File[numFiles];
        for (int i = 0; i < numFiles; i++) {
            certFiles[i] = new File(args[i + 2]);
            if (!certFiles[i].exists() || !certFiles[i].isFile()) {
                System.out.println("Erreur : Le fichier spécifié '" + certFiles[i].getPath() + "' n'existe pas ou n'est pas un fichier valide.");
                return;
            }
            System.out.println(getFileExtension(args[i + 2].toUpperCase()));
            System.out.println((args[1]).toLowerCase());
            if (!getFileExtension(args[i + 2]).equals((args[1]).toLowerCase())) {
                System.out.println("Erreur : Le fichier '" + args[i + 2] + "' n'a pas la même extension que le fichier '" + args[1].toLowerCase() + "'.");
                return;
            }
        }
    }
}
