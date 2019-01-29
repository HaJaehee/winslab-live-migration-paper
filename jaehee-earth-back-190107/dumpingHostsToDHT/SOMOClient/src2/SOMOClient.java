import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SOMOClient {
	
	public static final String OPCODE_BOOTUP = "00";
    public static final String OPCODE_GET_HASH = "01";
    public static final String OPCODE_GET_IP = "02";
    public static final String OPCODE_INFORM_CONNECTION = "03";
    public static final String OPCODE_APP_MOBILITY = "04";
    public static final String OPCODE_CTN_MOBILITY = "05";
    public static final String OPCODE_GET_IPPORT = "06";
    public static final String OPCODE_TOGGLE_LOGGING = "65";
	
	public static void main(String[] args){
		
		String hostname = "10.0.20.1";
		int port = 10002;

		
		try{
/*			String opCode = OPCODE_CTN_MOBILITY;
			String swNum = "02"; 
			String originalCtnIP = "0a000a02";
			String newCtnIP = "0a000a02";
			String newESIP = "0a000a01";
			String newHostIP = "0a000a02";
			String strInput = opCode+swNum+originalCtnIP+newCtnIP+newESIP+newHostIP; 
*/			
//			String opCode = OPCODE_GET_IP;
//			String swNum = "02";
//			String esIP = "0a001401";
//			String hash = "";
//			try {
//				hash = sha256("10.0.10.3");
//			} catch (NoSuchAlgorithmException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//			String strInput = opCode+swNum+esIP+hash;
			
			
//			String opCode = OPCODE_GET_HASH;
//			String swNum = "02";
//			String hostIP = "0a000a03";
//			String strInput = opCode+swNum+hostIP;
			
//			String opCode = OPCODE_INFORM_CONNECTION;
//			String swNum = "02";
//			String hostIP = "0a000a02";
//			String swIP = "0a000a01";
//			String strInput = opCode+swNum+hostIP+swIP;
//			
			String opCode = OPCODE_APP_MOBILITY;
			String swNum = "02";
			String originalHostIP = "0a000a02"; 
			//String portNumber = "1389";
			String portNumber = "0000";			
			String esIP = "0a000a01";
			String newHostIP = "0a000a02";
			String strInput = opCode+swNum+originalHostIP+portNumber+esIP+newHostIP;
			
			
//			String opCode = OPCODE_GET_IPPORT;
//			String swNum = "01"; 
//			String originalHostIP = "0a000a02";
//			String portNumber = "0050";
//			String strInput = opCode+swNum+originalHostIP+portNumber; 
			
//			String opCode = "OPCODE_TOGGLE_LOGGING";
//			String swNum = "01";
//			String strInput = opCode+swNum; 
			
			DatagramPacket outPacket;

			InetAddress server = InetAddress.getByName(hostname);

			DatagramSocket dSock = new DatagramSocket();

			byte[] data = hexToByteArray(strInput);

			outPacket = new DatagramPacket(data, data.length, server, port);

			System.out.println("dst address:"+outPacket.getAddress().toString());
			System.out.println("dst port:"+outPacket.getPort());
			System.out.println("pkt size:"+outPacket.getLength());
			
			dSock.send(outPacket);
            
            dSock.close();
		}catch(UnknownHostException e){
			e.printStackTrace();
		}catch(SocketException se){
			se.printStackTrace();
		}catch(IOException e){
			e.printStackTrace();
		}
	}
	
	// hex to byte[] 
	public static byte[] hexToByteArray(String hex) { 
		if (hex == null || hex.length() == 0) { 
			return null; 
			} 
		byte[] ba = new byte[hex.length() / 2]; 
		for (int i = 0; i < ba.length; i++) { 
			ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16); 
			} 
		return ba; 
	}
	
	// byte[] to hex 
	public static String byteArrayToHex(byte[] ba) { 
		if (ba == null || ba.length == 0) { 
			return null; 
			} 
		StringBuffer sb = new StringBuffer(ba.length * 2); 
		String hexNumber; 
		for (int x = 0; x < ba.length; x++) { 
			hexNumber = "0" + Integer.toHexString(0xff & ba[x]); 
			sb.append(hexNumber.substring(hexNumber.length() - 2)); 
			} 
		return sb.toString(); 
	} 
	
	static String sha256(String input) throws NoSuchAlgorithmException {
		MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
		byte[] result = mDigest.digest(input.getBytes());
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < result.length; i++) {
			sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return sb.toString();
	}
}
