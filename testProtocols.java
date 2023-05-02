import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 *
 */
public class testProtocols {

    protected Logger logger;
    protected static SSLSocketFactory factory = null;

    protected static List<String> protocolList = new ArrayList<>(
        Arrays.asList("TLSv1.2", "TLSv1.3", "TLSv1.1", "TLSv1")
    );

    public static void main(String args[]){
        String host = args[0];
        int port = Integer.parseInt(args[1]);

        try {
        for (String protocol : protocolList) { 
        	System.out.println("Connecting to " + host + ":" + port + " with protocol:" + protocol);
  		clientConnection(protocol);
    		connectHostPort(host, port);  
                System.out.println("\n");
        }  
        } catch (Throwable t) {
                System.out.println("Exception while getting SSLContext: " + t);
        }
    }

    private static void clientConnection(String protocol) {

        try {
            SSLContext sc = SSLContext.getInstance(protocol);
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            sc.getSupportedSSLParameters().setProtocols(new String[] { "TLSv1.2" , "TLSv1.3"});

            factory = new MySSLSocketFactory(sc, protocol);

        } catch (Throwable t) {
            System.out.println("\tException while getting SSLContext: " + t);
        }

    }

    private static TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] { null };
        }

        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
    } };

    public String callURL(URL url) {
        System.out.println("Calling " + url.toString());
        StringBuilder sb = new StringBuilder();

        try {

            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

            con.setSSLSocketFactory(factory);
            con.setDoInput(true);
            con.setDoOutput(true);
            con.setUseCaches(false);
            con.setRequestMethod("GET");

            java.io.InputStream is = con.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line = null;

            System.out.println("Building StringBuffer with response:");
            while ((line = br.readLine()) != null) {
                System.out.println(line);
                sb.append(line);
            }

            br.close();
            con.disconnect();
            return (sb.toString());
        } catch (Throwable t) {
            sb.append(t.toString());
            return sb.toString();
        }
    }

    public static String connectHostPort(String host, int port) throws IOException {
        StringBuilder sb = new StringBuilder();
        SSLSocket socket = null;

        try {
            socket = (SSLSocket) factory.createSocket(host, port);

            socket.startHandshake();
            String connectionProtocol = socket.getSession().getProtocol();
            System.out.println("\tConnection made with " + connectionProtocol);

        } catch (Throwable t) {
            System.out.println("\tException connecting: " + t.getMessage()); 
            sb.append(t.toString());
        }
        socket.close();
        return sb.toString();
    }

    private static class MySSLSocketFactory extends SSLSocketFactory {

        public MySSLSocketFactory(SSLContext ctx, String protocol) throws Exception {
            //System.out.println("initializing the factory");
            initMySSLSocketFactory(ctx, protocol);
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return m_ciphers;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return m_ciphers;
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            SSLSocketFactory factory = m_ctx.getSocketFactory();
            SSLSocket ss = (SSLSocket) factory.createSocket(s, host, port, autoClose);

            ss.setEnabledCipherSuites(m_ciphers);
            //ss.setEnabledProtocols(m_protocol);

            return ss;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            SSLSocketFactory factory = m_ctx.getSocketFactory();
            SSLSocket ss = (SSLSocket) factory.createSocket(address, port, localAddress, localPort);

            ss.setEnabledCipherSuites(m_ciphers);
            //ss.setEnabledProtocols(m_protocol);

            return ss;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            SSLSocketFactory factory = m_ctx.getSocketFactory();
            SSLSocket ss = (SSLSocket) factory.createSocket(host, port, localHost, localPort);

            ss.setEnabledCipherSuites(m_ciphers);
            //ss.setEnabledProtocols(m_protocol);

            return ss;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            SSLSocketFactory factory = m_ctx.getSocketFactory();
            SSLSocket ss = (SSLSocket) factory.createSocket(host, port);

            ss.setEnabledCipherSuites(m_ciphers);
            //ss.setEnabledProtocols(m_protocol);

            return ss;
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            SSLSocketFactory factory = m_ctx.getSocketFactory();
            SSLSocket ss = (SSLSocket) factory.createSocket(host, port);

            ss.setEnabledCipherSuites(m_ciphers);
            //ss.setEnabledProtocols(m_protocol);

            return ss;
        }

        private void initMySSLSocketFactory(SSLContext ctx, String protocol) throws Exception {
            //System.out.println("Setting up the protocols and ciphers");
            m_ctx = ctx;
            m_protocol = new String[] { protocol };

            SSLParameters params = m_ctx.getSupportedSSLParameters();
            m_ciphers = params.getCipherSuites();
        }

        private String[] m_ciphers = null;
        private String[] m_protocol = null;
        private SSLContext m_ctx;
    }
}

