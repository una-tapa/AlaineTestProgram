import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;


public class ServerJsse {
    static int N = 50, L = 100, R = 2;

    ServerJsse() {
        super();
    }

    static SSLContext sslContext;

    private static void initContext() {
        try {

	    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("key.jks"), "Liberty".toCharArray());
            kmf.init(ks, "Liberty".toCharArray());
	    KeyManager keyMgrs[] = kmf.getKeyManagers();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyMgrs, tmf.getTrustManagers(), null);
        } catch (Throwable e) {
            System.out.println("Failed to read testkeys file.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main(String args[]) {
        int i, j, len;

        if (args.length > 0)
            N = Integer.parseInt(args[0]);
        if (args.length > 1)
            L = Integer.parseInt(args[1]);

        byte buffer[] = new byte[L];


        System.out.println("SERVER: started.");

        initContext();

        try {

            // Get and print the list of supported enabled cipher suites
            System.out.println("ServerJsse: SSL server context created.");
            String supported[] = sslContext.getSocketFactory().getSupportedCipherSuites();


            // Create an SSL session over port 8050
            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            SSLServerSocket ssl_server_sock = (SSLServerSocket)factory.createServerSocket(8050);
//            ssl_server_sock.setEnabledCipherSuites(supported);
//	    ssl_server_sock.setEnabledProtocols(new String[] { "TLSv1.2" });
			
			
            SSLSocket ssl_sock; 
            InputStream istr;
            OutputStream ostr;
            long t;
            while (buffer[0] != -1) {
                for (int n=0; n<R; n++) {
                    try {
                        ssl_sock = (SSLSocket)(ssl_server_sock.accept());

                        ssl_sock.startHandshake();
                        SSLSession session = ssl_sock.getSession();
                        System.out.println("\nServerJsse: SSL connection established");
                        System.out.println("   cipher suite:       " + session.getCipherSuite());
                        System.out.println("   ssl protocol:       " + session.getProtocol());
                    } catch (IOException se) {
                        System.out.println("\nServerJsse: client connection refused\n" + se);
                        break;
                    }

                    if (L > 0) {
                        istr = ssl_sock.getInputStream();
                        ostr = ssl_sock.getOutputStream();

                        t = System.currentTimeMillis(); 
                        for (j=0;j<N;j++) {
                            for (len = 0;;) {
                                try {
                                    if ((i = istr.read(buffer, len, L-len)) == -1) {
                                        System.out.println("ServerJsse: connection dropped by partner.");
                                        ssl_sock.close();
                                        return;
                                    }
                                } catch (InterruptedIOException e) {
                                    System.out.println("waiting");
                                    continue;
                                }
                                if ((len+=i) == L) break;
                            }
                            ostr.write(buffer, 0, L);
                        }
                        System.out.println("Messages = " + N*2 + "; Time = " +
                                           (System.currentTimeMillis() - t));
                    }
                    ssl_sock.close();
                }
            }
            ssl_server_sock.close();
            System.out.println("\nServerJsse: SSL connection closed.");
            Thread.sleep(1000);

            // plain socket benchmark
            if (L > 0) {
                // Socket bench
                ServerSocket server_sock = new ServerSocket(8050);
                Socket sock = server_sock.accept();
                System.out.println("\nServerJsse: Socket connection accepted.");
                istr = sock.getInputStream();
                ostr = sock.getOutputStream();

                t = System.currentTimeMillis();
                for (j=0;j<N;j++) {
                    for (len = 0;;) {
                        if ((i = istr.read(buffer, len, L-len)) == -1) {
                            System.out.println("ServerJsse: connection dropped by partner.");
                            return;
                        }
                        if ((len+=i) == L) break;
                    }
                    ostr.write(buffer, 0, L);
                }
                System.out.println("Messages = " + N*2 + "; Time = " +
                                   (System.currentTimeMillis() - t));
                sock.close();
                server_sock.close();
                System.out.println("\nServerJsse: Socket connection closed.");
                Thread.sleep(1000);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException f) {
            f.printStackTrace();
        }
        System.out.println("ServerJsse: terminated.");
    }
}
