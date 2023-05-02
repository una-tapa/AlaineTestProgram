
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.*;
import javax.net.ssl.SSLSocketFactory;
import javax.net.SocketFactory;
import java.security.cert.Certificate;
import com.ibm.security.certclient.util.PkSsCertFactory;
import com.ibm.security.certclient.util.PkSsCertificate;
import com.ibm.security.certclient.util.PkNewCertificate;
import com.ibm.security.certclient.util.PkNewCertFactory;
import java.util.Date;
import java.text.DateFormat;

public class newCert
{

	public static void main(String[] args)
	{
		try {
			Date deltaDate = new Date();
			deltaDate.setTime(deltaDate.getTime() - (1 * 24 * 60 * 60 * 1000L));
			
			java.util.List san = new java.util.ArrayList();
			san.add("user@domain");
			san.add("localhost");
			san.add("http://localhost");
			san.add("127.0.0.1");
			san.add("file:/c/foo");
			
			PkSsCertificate SsCert = PkSsCertFactory.newSsCert(
					2048,
					"RSA",
					"SHA256withRSA",
					"CN=localhost,OU=root",
					365,
					deltaDate,
					true,
					san,
					null,
					null,
					"IBMJCE",
					null,
					true);

			X509Certificate rootCert = SsCert.getCertificate();
			X509Certificate[] rootChain = new X509Certificate[1];
			rootChain[0] = rootCert;
			PrivateKey rootPrivateKey = SsCert.getKey();
			//System.out.println("root cert is " + rootCert);

			//Create a certificate signed with the root
			PkNewCertificate chainCert = PkNewCertFactory.newCert(2024,
					"CN=localhost,OU=leaf",
					365,
					deltaDate,
					true,
					san,
					null,
					null,
					"IBMJCE",
					null,
					rootChain,
					rootPrivateKey,
					true);

			//Lets see if we get a certificate chain from the newly created chained cert
			X509Certificate[] chainedCert = chainCert.getCertificateChain();

			for (int i=0; i< chainedCert.length; i++) {
				System.out.println("CERT chain number " + i + " is: ");
				System.out.println(chainedCert[i]);
			}

			//Set the certificate to a PKCS12 keystore
			KeyStore ks = KeyStore.getInstance("PKCS12");
			File file = new File("testKey.p12");
			if (file.exists()){
				ks.load(new FileInputStream(file), "123456".toCharArray());
			} else {
				ks.load(null, null);
			}

			ks.setKeyEntry("test", chainCert.getKey(), 
					"123456".toCharArray(),
					chainedCert);

			ks.store(new FileOutputStream(file), "123456".toCharArray());


		} catch (Exception e ) {
			System.out.println("exception " + e.getMessage());
		}

	}

}


