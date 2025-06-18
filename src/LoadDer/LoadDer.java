package LoadDer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

public class LoadDer {
    public static void trans(String AnswerSection) {
        try {
            ProcessBuilder pb = new ProcessBuilder("py", "load_der.py");
            Process process = pb.start();
            OutputStreamWriter writer = new OutputStreamWriter(process.getOutputStream());
            writer.write(AnswerSection.toString());
            writer.flush();
            writer.close();

            BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String inputLine;
            while ((inputLine = inputReader.readLine()) != null) {
                System.out.println(inputLine);
            }

            inputReader.close();
            process.waitFor();

        } catch (IOException | InterruptedException e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }
    public static void trans2(String privkey, String cert) {
        try {
            ProcessBuilder pb = new ProcessBuilder("py", "load_der copy.py");
            Process process = pb.start();
            
            try (OutputStreamWriter writer = new OutputStreamWriter(process.getOutputStream())) {
                writer.write(privkey + "\n");
                writer.write(cert + "\n");
                writer.flush();
                writer.close();
            }

            BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String inputLine;
            while ((inputLine = inputReader.readLine()) != null) {
                System.out.println(inputLine);
            }

            inputReader.close();
            process.waitFor();

        } catch (IOException | InterruptedException e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }
}
