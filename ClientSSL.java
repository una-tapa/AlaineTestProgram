import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;

public class ClientSSL {

  private static final String HOST = "localhost";

  private static final int PORT = 8050;

  public static void main(String[] args) throws Exception {

	SSLContext sslContext = null;

        try {

	    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("key.jks"), "Liberty".toCharArray());
            kmf.init(ks, "Liberty".toCharArray());
	    KeyManager keyMgrs[] = kmf.getKeyManagers();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(keyMgrs, tmf.getTrustManagers(), null);
        } catch (Throwable e) {
            System.out.println("Failed to read testkeys file.");
            e.printStackTrace();
            System.exit(1);
        }



    SSLSocketFactory sf = sslContext.getSocketFactory(); 
    Socket s = sf.createSocket(HOST, PORT);
    OutputStream out = s.getOutputStream();
    out.write("\nConnection established.\n\n".getBytes());
    out.flush();
    int theCharacter = 0;
    theCharacter = System.in.read();
    while (theCharacter != '~') // The '~' is an escape character to exit
    {
      out.write(theCharacter);
      out.flush();
      theCharacter = System.in.read();
    }

    out.close();
    s.close();
  }
}
