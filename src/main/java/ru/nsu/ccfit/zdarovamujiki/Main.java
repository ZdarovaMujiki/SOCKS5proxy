package ru.nsu.ccfit.zdarovamujiki;

import lombok.extern.java.Log;
import java.util.logging.Level;

@Log
public class Main {
    public static void main(String[] args) {
        try {
            Proxy proxy = new Proxy();
            int port = Integer.parseInt(args[0]);
            proxy.start(port);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            log.log(Level.WARNING, "Bad port");
        }
    }
}