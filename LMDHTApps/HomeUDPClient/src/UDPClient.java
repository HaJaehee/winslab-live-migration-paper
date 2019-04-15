import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;

public class UDPClient {
  	
	public UDPClient () {
		
	}
	
	public static void main(String[] args) {
	  	int serverPort = 20002;
	  	Socket sock;
		try {
			sock = new Socket("10.0.20.2", serverPort);
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
					sock.getOutputStream(),Charset.forName("UTF-8")));

		  	out.write("Hello Java UDP Server!!!! \n");
		  	out.flush();
		  	out.close();
		  	sock.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	  	

	}

}
