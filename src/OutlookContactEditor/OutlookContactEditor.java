package OutlookContactEditor;

import com.jacob.com.*;
import com.jacob.activeX.*;

public class OutlookContactEditor {

    public static void openEditor(String email) {
        ActiveXComponent outlook = new ActiveXComponent("Outlook.Application");

        Dispatch application = outlook.getObject();
        try {
            Dispatch session = Dispatch.call(application, "GetNamespace", "MAPI").toDispatch();

            Dispatch contactsFolder = Dispatch.call(session, "GetDefaultFolder", 10).toDispatch();

            Dispatch items = Dispatch.get(contactsFolder, "Items").toDispatch();
            Dispatch item = Dispatch.call(items, "Find", "[Email1Address] = '" + email + "'").toDispatch();

            if (item != null) {
                System.out.println("Found contact: " + Dispatch.get(item, "FullName").toString());

                Dispatch.call(item, "Display");
            } else {
                System.out.println("Contact not found!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
