import java.net.UnknownHostException;
import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;

public class UDPServer {
	public static void main(String[] args) {	
		
		int port = 20003;
		ServerSocket server = null;
        while(true){
            try {
                if (server == null) {
                    server = new ServerSocket(port);
                }
                while(true){
                    Socket sock = server.accept();
                    
                    System.out.println("Client : " + sock.getInetAddress());
                    
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(sock.getInputStream(),Charset.forName("UTF-8")));
                    
                    String inputLine = in.readLine();
                    System.out.println("Data : " + inputLine);
                    
                    in.close();
                    sock.close();
                    
                    String[] cmd = {"/bin/bash","-c","echo wins2-champion | sudo -S virsh net-update --network default --command add-last --section ip-dhcp-host --xml \"<host mac='52:54:00:06:7d:f7' ip='10.48.0.4' />\" --live --config"};
                    Runtime.getRuntime().exec(cmd);


                    int serverPort = 12345;
                    Socket sock2;
                    try {
                           sock2 = new Socket("192.168.122.2", serverPort);
                           BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                           sock2.getOutputStream(),Charset.forName("UTF-8")));

                           out.write("10.48.0.4,10.48.0.1");
                           out.flush();
                           out.close();
                           sock2.close();
                    } catch (UnknownHostException e) {}
                }

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } finally {
            }
        }		
	}
}
