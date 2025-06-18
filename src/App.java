// import GetSMIMEA.GetSMIMEA;
// import LoadDer.LoadDer;
// import SmimeaRecordGenerator.SmimeaRecordGenerator;

// import java.util.Scanner;

// import CAApiClient.CAApiClient;
// import ExtractAnswerSection.ExtractAnswerSection;

// import InstallCertificate.InstallCertificate;

import ui.MailAppUI;

public class App {
    public static void main(String[] args) throws Exception {
        // Scanner scanner = new Scanner(System.in);
        // System.out.println("kind: ");
        // String kind = scanner.nextLine();
        // System.out.println("url: ");
        // String url = scanner.nextLine();


        // if (kind.equals("send")) {
        //     InstallCertificate.installCertificate(url);

        //     String queryResult = SmimeaRecordGenerator.trans(url);
        //     System.out.println(queryResult);

        //     GetSMIMEA.getSMIMEA(queryResult);

        //     String AnswerSection = ExtractAnswerSection.extract();
        //     System.out.println(AnswerSection);

        //     LoadDer.trans(AnswerSection);

        // }
        // else if (kind.equals("create")) {
        //     CAApiClient.create(url);
        //     System.out.println("code: ");
        //     String code = scanner.nextLine();
        //     scanner.close();
        //     CAApiClient.verifySubscription(url, code);
        // }
        // scanner.close();

        javax.swing.SwingUtilities.invokeLater(() -> new MailAppUI());
    }
}
