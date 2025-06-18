package ExtractAnswerSection;

import java.io.BufferedReader;
import java.io.FileReader;

public class ExtractAnswerSection {
    public static String extract() {
        String line = "";
        try {
            BufferedReader reader = new BufferedReader(new FileReader("test.out"));

            boolean foundAnswerSection = false;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
                if (foundAnswerSection) {
                    break;
                }
                if (line.startsWith(";; ANSWER SECTION:")) {
                    foundAnswerSection = true;
                }
            }

            reader.close();
        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
        }

        System.out.println(line);

        if (line == null) {
            return null;
        }

        int index = line.indexOf("SMIMEA");
        String substring = "";
        if (index != -1) {
            substring = line.substring(index + "SMIMEA 3 0 0".length()).trim();
        }
        return substring;
    }
}
