import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Random;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.tomp2p.connection.Bindings;
import net.tomp2p.futures.BaseFutureAdapter;
import net.tomp2p.futures.FutureBootstrap;
import net.tomp2p.futures.FutureDHT;
import net.tomp2p.p2p.Peer;
import net.tomp2p.p2p.PeerMaker;
import net.tomp2p.peers.Number160;
import net.tomp2p.storage.Data;
import net.tomp2p.futures.FutureDiscover;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;

/*
 * Update 2020/03/04
 *              Update history: LM-MEC(2019) v1.3.9
 *			Switch IPs are rollback.
 */
public final class LMDHTServer {
    public static String[] swIPAddrList = {"10.16.0.1","10.32.0.1","10.48.0.1","10.0.40.1","10.0.50.1","10.64.0.1"};
    public static short edgeSWList[] = {1,2,3,0,0,6};
    public static int swCount = swIPAddrList.length;
    //public static Channel clientCh;
    public static int PORT;
    public static int nodeIndex;
    public static DHTServer kserver = null;
    public static boolean logging = true;
    public static boolean logFileOut = false;
    public static String[] input = null;
    public static int ksvrPort = 8468;
    public static int ovsPort = 9999;
    public static Bootstrap bClient;

   
    
    public static void main(String[] args) throws Exception {
	
    	//input = new String[] {"0"};
    	
	    if (input == null) {
			if (args.length == 1) {
				if(LMDHTServer.logging)System.out.println("The First node begins");
				kserver = new DHTServer(Integer.parseInt(args[0]));
				if(LMDHTServer.logging)System.out.println("Bootstrap is done");
			}
			else if (args.length == 3) {
				if(LMDHTServer.logging)System.out.println("Connect to master node");
				kserver = new DHTServer(Integer.parseInt(args[0]),args[1],Integer.parseInt(args[2]));
				if(LMDHTServer.logging)System.out.println("Bootstrap is done");
			}
			else{
				if(LMDHTServer.logging)System.out.println("Ambiguous Input. Usage: java LMDHTServer [nodeNum] {[bootstrap ip] [boostrap port]}");
				return;
			}
			nodeIndex = Integer.parseInt(args[0]);
	    } else {
	    	if (input.length == 1) {
				if(LMDHTServer.logging)System.out.println("The First node begins");
				kserver = new DHTServer(Integer.parseInt(input[0]));
				if(LMDHTServer.logging)System.out.println("Bootstrap is done");
			}
			else if (input.length == 3) {
				if(LMDHTServer.logging)System.out.println("Connect to master node");
				kserver = new DHTServer(Integer.parseInt(input[0]),input[1],Integer.parseInt(input[2]));
				if(LMDHTServer.logging)System.out.println("Bootstrap is done");
			}
	    	nodeIndex = Integer.parseInt(input[0]);
	    }

        EventLoopGroup groupClient = new NioEventLoopGroup();
        bClient = new Bootstrap();
        bClient.group(groupClient)
        		.channel(NioDatagramChannel.class)
                .handler(new ClientHandler());
        
        Thread.sleep(1000);
		
        //clientCh = bClient.bind(0).sync().channel();
        
        
        PORT = 10000 + nodeIndex+1;
        System.out.println("port "+PORT+" is opened.");
        Bootstrap b = new Bootstrap();
        EventLoopGroup group = new NioEventLoopGroup();
        try{
        	b.group(group)
        		.channel(NioDatagramChannel.class)
        		.handler(new LMDHTServerHandler(nodeIndex));
        	b.bind(PORT).sync().channel().closeFuture().await();
        }
        catch (Exception e) {
        	e.printStackTrace();
        }
        finally{
        	group.shutdownGracefully();
        }
    }
}


class LMDHTServerHandler extends SimpleChannelInboundHandler<DatagramPacket> {
	
	private static final byte OPCODE_BOOTUP = 0;
    private static final byte OPCODE_GET_HASH = 1;
    private static final byte OPCODE_GET_IP = 2;
    private static final byte OPCODE_INFORM_CONNECTION = 3;
    private static final byte OPCODE_APP_MOBILITY = 4;
    private static final byte OPCODE_CTN_MOBILITY = 5;
    private static final byte OPCODE_GET_IPPORT = 6;
    private static final byte OPCODE_TOGGLE_LOGGING = 101;
	
    private static final byte OPCODE_SET_SWTYPE = 0;
    private static final byte OPCODE_QUERIED_HASH = 1;
    private static final byte OPCODE_QUERIED_IP = 2;
    private static final byte OPCODE_UPDATE_IP = 3;
    private static final byte OPCODE_NEW_APP = 4;
    private static final byte OPCODE_NEW_CTN = 5;
    
    private static final int LM_HDR_LENGTH = 32;
    
    public LMDHTServerHandler(int nodeIndex) throws InterruptedException{
        super();
        
        int sendBufLength = 5 + 2*LMDHTServer.swCount;
    	byte[] sendBuf = new byte[sendBufLength];
        sendBuf[0] = OPCODE_SET_SWTYPE;
        sendBuf[1] = (byte)LMDHTServer.edgeSWList[nodeIndex];//switch num
        sendBuf[2] = (byte)0x02;//switch type

        byte[] lengthBytes = ByteBuffer.allocate(2).putShort((short)LMDHTServer.swCount).array();
        sendBuf[3] = lengthBytes[0];
        sendBuf[4] = lengthBytes[1];
        
        //appends edge switch numbers to byte array 
        for (int i = 0; i < LMDHTServer.swCount; i++){
            if (LMDHTServer.edgeSWList[i] != 0){
                byte[] swBytes = ByteBuffer.allocate(2).putShort((short)(LMDHTServer.edgeSWList[i]-1)).array();
                sendBuf[5 + i*2] = swBytes[0];
                sendBuf[5 + i*2+1] = swBytes[1];
            }
        }
        if(LMDHTServer.logging) {
        	System.out.printf("wake up signal to ovs:");
        
			for (int i = 0;i < sendBufLength;i++){
				System.out.printf("%02x",sendBuf[i]);
			}
			System.out.println();
        }
        
        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
        //wake up signal to ovs
        clientCh.writeAndFlush(
            new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);

    }

    int fromByteArray(byte[] bytes) {
        return ByteBuffer.wrap(bytes).getInt();
    }
    int iptoint(String ipAddr) throws UnknownHostException{
        int result = 0;
        for (byte b: ipStringToByte(ipAddr))
        {
            result = result << 8 | (b & 0xFF);
        }
        return result;
    }
    byte[] ipStringToByte(String ipAddr) throws UnknownHostException{
        InetAddress ipAddress= null;
        ipAddress= InetAddress.getByName(ipAddr);
        return ipAddress.getAddress();
    }
    long ntohl(long network){
        network = network & 0xFFFFFFFF;
        long b1 = network & 0xFF000000;
        long b2 = network & 0x00FF0000;
        long b3 = network & 0x0000FF00;
        long b4 = network & 0x000000FF;
        network = b4 << 24 | b3 << 8 | b2 >> 8 | b1 >> 24;
        return network;
    }
    int ntohs(int network){
        network = network & 0xFFFF;
        int b1 = network & 0xFF00;
        int b2 = network & 0x00FF;
        network = b2 << 8 | b1 >> 8;
        return network;
    }
    
    @Override
    public void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) throws UnknownHostException, InterruptedException, Exception {
    	//if(LMDHTServer.logging)System.err.println(packet.content().toString(CharsetUtil.UTF_8));
        ByteBuf payload = packet.content();
        
        //if(LMDHTServer.logging)System.out.println("[Node "+LMDHTServer.nodeNum+"] Received Message: "+payload.toString());

        byte opCode = payload.readByte();
        byte switchNum = payload.readByte();
        byte switchIndex = (byte)(switchNum-1); 
        //nHost is originally 4byte value
        long nHost = ntohl(payload.readUnsignedInt());
        int nHostInt = (int)nHost & 0xFFFFFFFF;
        byte[] byteHostIP = ByteBuffer.allocate(4).putInt(nHostInt).array();
       
        String strIP = String.format("%d.%d.%d.%d",(nHost & 0xFF), (nHost >> 8 & 0xFF), (nHost >> 16 & 0xFF), (nHost >> 24 & 0xFF));
        if(LMDHTServer.logging)System.out.printf("[Node %d] Received Message: opCode=%d,  switchNum=%d, IP=%s, SWIP = %s\n",LMDHTServer.nodeIndex, opCode, switchNum, strIP, "127.0.0.1");
        
        if (opCode == OPCODE_BOOTUP){
        	if(LMDHTServer.logging)System.out.println("opCode 0: show edge switchs list");
            if(LMDHTServer.logging)System.out.println("opCode 0 will be supported soon");
            
        } /*else if (opCode == OPCODE_GET_HASH){  //deprecated by jaehee 170414
        	if(LMDHTServer.logging)System.out.println("opCode 1: get Object ID from DHT server with digested IP");
        	//make Object ID and query to DHT table
			MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
			byte[] strDig = mDigest.digest(strIP.getBytes());
	
			if(LMDHTServer.logging)System.out.println("Hashed IP: "+strDig+", length: "+strDig.length);
			LMDHTServer.kserver.get(opCode, strIP, switchNum, byteHostIP, strDig);
			
			//---------------client example
//			String opCode = OPCODE_GET_HASH;
//			String swNum = "02";
//			String hostIP = "0a000a03";
//			String strInput = opCode+swNum+hostIP;

        }*/ else if (opCode == OPCODE_GET_IP){
        	if(LMDHTServer.logging)System.out.println("opCode 2: get Host IP from DHT server with Object ID");
        	//copy payload(Object ID) to strDig byte array and query to DHT table
			byte[] strDig = new byte[LM_HDR_LENGTH]; //Jaehee modified 160720
			
			for (int i = 0;i < LM_HDR_LENGTH;i++){ //Jaehee modified 160720
				strDig[i] = payload.readByte();
				
			}
			if(LMDHTServer.logging){
				System.out.println("Object ID: ");
			
				for (int i = 0;i < LM_HDR_LENGTH;i++){ 
					System.out.printf("%02x",(strDig[i]&0xff));
				}
				System.out.println();
			}
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < strDig.length; i++) {
				sb.append(Integer.toString((strDig[i] & 0xff) + 0x100, 16)
						.substring(1));
			}

			
			LMDHTServer.kserver.get(opCode, sb.toString(), switchNum, byteHostIP, strDig);
			
			//---------------client example
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
			
        } else if (opCode == OPCODE_INFORM_CONNECTION){
        	if(LMDHTServer.logging)System.out.println("opCode 3: store DHT server");
            
            //byte[] byte_switch_ip = new byte[4];
            String strSWIP = LMDHTServer.swIPAddrList[switchIndex];
            int nSwitchIP = iptoint(strSWIP) & 0xFFFFFFFF;
            byte[] reverseByteSwitchIP =  ByteBuffer.allocate(4).putInt(nSwitchIP).array();
            byte[] byteSwitchIP = new byte[4];
            for (int i = 0;i < 4;i++) {
            	byteSwitchIP[3-i] = reverseByteSwitchIP[i];
            }

            if(LMDHTServer.logging)System.out.printf("[Node %d] Storing the pair: (Host IP=%s, Switch IP=%s)\n", LMDHTServer.nodeIndex,strIP,strSWIP);
          
            LMDHTServer.kserver.store(strIP, byteHostIP, byteSwitchIP);

            byte[] sendBuf = new byte[42];
            sendBuf[0] = OPCODE_UPDATE_IP;
            for (int i = 0;i < 4;i++){
                    sendBuf[2 + (3-i)] = byteHostIP[i];
                    sendBuf[6 + (3-i)] = byteSwitchIP[i];
            }
            
			MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
			byte[] strDig = mDigest.digest(strIP.getBytes());
            
			for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 170329
				sendBuf[10+i]=  strDig[i];
			}
			
			if(LMDHTServer.logging){
				System.out.println("Object ID: ");
			
				for (int i = 0;i < LM_HDR_LENGTH;i++){ 
					System.out.printf("%02x",(strDig[i]&0xff));
				}
				System.out.println();
			}
			for (int i = 0;i < LMDHTServer.swCount;i++){
				if (LMDHTServer.edgeSWList[i] != 0 && LMDHTServer.edgeSWList[i] != switchNum){

                    byte[] swByte = ByteBuffer.allocate(2).putShort(LMDHTServer.edgeSWList[i]).array();
				    sendBuf[1] = swByte[1];
				    int swListIndex = LMDHTServer.edgeSWList[i]-1;
				    

			        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
                    clientCh.writeAndFlush(
    	                        new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress(LMDHTServer.swIPAddrList[swListIndex],LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
                }
			}
			byte[] swByte = ByteBuffer.allocate(2).putShort(switchNum).array();
			sendBuf[1] = swByte[1];
			if(LMDHTServer.logging)System.out.printf("receiving SW IP="+"127.0.0.1"+",port="+LMDHTServer.ovsPort+"\n");

	        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
			
			clientCh.writeAndFlush(
    	         new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress("127.0.0.1",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
			
			
//			String opCode = OPCODE_INFORM_CONNECTION;
//			String swNum = "02";
//			String hostIP = "0a000a02";
//			String swIP = "0a000a01";
//			String strInput = opCode+swNum+hostIP+swIP;

        } else if (opCode == OPCODE_APP_MOBILITY){
        	if(LMDHTServer.logging)System.out.println("opCode 4: application mobility");
        
            byte[] byteHomeTargetHostIP = byteHostIP;
            String strHomeTargetHostIP = strIP;
            
            byte[] bytePortNumber = {payload.readByte(),payload.readByte()};
            String strPortNumber = ":"+((bytePortNumber[1] & 0xFF) + ((bytePortNumber[0] & 0xFF)*0x100));
            
            long nVisitingESIP = ntohl(payload.readUnsignedInt());
            int nVisitingESIPInt = (int)nVisitingESIP & 0xFFFFFFFF;
            byte[] byteVisitingESIP = ByteBuffer.allocate(4).putInt(nVisitingESIPInt).array();
            
            long nVisitingTargetHost = ntohl(payload.readUnsignedInt());
            int nVisitingTargetHostInt = (int)nVisitingTargetHost & 0xFFFFFFFF;
            byte[] byteVisitingTargetHostIP = ByteBuffer.allocate(4).putInt(nVisitingTargetHostInt).array();
            String strVisitingTargetHostIP = String.format("%d.%d.%d.%d",(nVisitingTargetHost & 0xFF), (nVisitingTargetHost >> 8 & 0xFF), (nVisitingTargetHost >> 16 & 0xFF), (nVisitingTargetHost >> 24 & 0xFF));
            
            if(LMDHTServer.logging){
            	
	            String strVisitingESIP = String.format("%d.%d.%d.%d",(nVisitingESIP & 0xFF), (nVisitingESIP >> 8 & 0xFF), (nVisitingESIP >> 16 & 0xFF), (nVisitingESIP >> 24 & 0xFF));
	            
	            
	            System.out.printf("[Node %d] Storing the pair: (Original Host IP=%s, Port Number=%s, New Host IP=%s, New Edge Switch IP=%s)\n", LMDHTServer.nodeIndex, strHomeTargetHostIP, strPortNumber, strVisitingTargetHostIP, strVisitingESIP);
            }
            
            LMDHTServer.kserver.store(strHomeTargetHostIP+strPortNumber, strVisitingTargetHostIP+strPortNumber, byteVisitingTargetHostIP, byteVisitingESIP, byteHomeTargetHostIP);
            
            byte[] sendBuf = new byte[48];
            
            sendBuf[0] = OPCODE_NEW_APP;
            for (int i = 0;i < 4;i++){
                sendBuf[2 + (3-i)] = byteHomeTargetHostIP[i];
                sendBuf[6 + (3-i)] = byteVisitingESIP[i];
                sendBuf[10 + (3-i)] = byteVisitingTargetHostIP[i];               
            }
            for (int i = 0;i < 2;i++){
            	sendBuf[14 + i] = bytePortNumber[i];
            }
            
			MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
			byte[] strDig = mDigest.digest((strHomeTargetHostIP+strPortNumber).getBytes());
            
			for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 170329
				sendBuf[16+i]=  strDig[i];
			}
            
			if(LMDHTServer.logging){
				System.out.println("Object ID: ");
			
				for (int i = 0;i < LM_HDR_LENGTH;i++){ 
					System.out.printf("%02x",(strDig[i]&0xff));
				}
				System.out.println();
			}
			
			for (int i = 0;i < LMDHTServer.swCount;i++){
                if (LMDHTServer.edgeSWList[i] != 0 && LMDHTServer.edgeSWList[i] != switchNum){

				    byte[] swByte = ByteBuffer.allocate(2).putShort(LMDHTServer.edgeSWList[i]).array();
				    sendBuf[1] = swByte[1];
				    int swListIndex = LMDHTServer.edgeSWList[i]-1;
					if(LMDHTServer.logging)System.out.printf("receiving SW IP="+LMDHTServer.swIPAddrList[swListIndex]+",port="+LMDHTServer.ovsPort+"\n");
                   

			        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
					
					clientCh.writeAndFlush(
    	                        new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress(LMDHTServer.swIPAddrList[swListIndex],LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
                }
			}
			byte[] swByte = ByteBuffer.allocate(2).putShort(switchNum).array();
			sendBuf[1] = swByte[1];
			if(LMDHTServer.logging)System.out.printf("receiving SW IP="+"127.0.0.1"+",port="+LMDHTServer.ovsPort+"\n");
			

	        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
			clientCh.writeAndFlush(
    	         new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress("127.0.0.1",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
			
			/*
			for (int i = 0;i < 4;i++){
                sendBuf[2 + (3-i)] = byteVisitingTargetHostIP[i];
                sendBuf[6 + (3-i)] = byteVisitingESIP[i];
                sendBuf[10 + (3-i)] = byteHomeTargetHostIP[i];               
            }
			strDig = mDigest.digest((strVisitingTargetHostIP+strPortNumber).getBytes());
			
			for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 170329
				sendBuf[16+i]=  strDig[i];
			}

			for (int i = 0;i < LMDHTServer.swCount;i++){
				byte[] swByte = ByteBuffer.allocate(2).putShort(LMDHTServer.edgeSWList[i]).array();
				sendBuf[1] = swByte[1];
				int swListIndex = LMDHTServer.edgeSWList[i]-1;
                	     
		        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
                clientCh.writeAndFlush(
    	                        new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress(LMDHTServer.swIPAddrList[swListIndex],LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);

			}*/

            //---------------client example
//			String opCode = OPCODE_APP_MOBILITY;
//			String swNum = "02";
//			String homeTargetHostIP = "0a000a01"; 
//			String portNumber = "0050";
//			String esIP = "0a001401";
//			String newHostIP = "0a001402";
//			String strInput = opCode+swNum+homeTargetHostIP+portNumber+esIP+newHostIP;
     
            
            //if ("Quote".equals(packet.content().toString(CharsetUtil.UTF_8))) {
        //    ctx.write(new DatagramPacket(Unpooled.copiedBuffer("Quote" + nextQuote(), CharsetUtil.UTF_8), packet.sender()));
        //}
        
        } else if (opCode == OPCODE_CTN_MOBILITY){
        	if(LMDHTServer.logging)System.out.println("opCode 5: container mobility");
            
            byte[] byteHomeCTIP = byteHostIP;
            String strHomeCTIP = strIP;
            
            long nVisitingCT = ntohl(payload.readUnsignedInt());
            int nVisitingCTInt = (int)nVisitingCT & 0xFFFFFFFF;
            byte[] byteVisitingCTIP = ByteBuffer.allocate(4).putInt(nVisitingCTInt).array();
            String strVisitingCTIP = String.format("%d.%d.%d.%d",(nVisitingCT & 0xFF), (nVisitingCT >> 8 & 0xFF), (nVisitingCT >> 16 & 0xFF), (nVisitingCT >> 24 & 0xFF));
            
            long nVisitingESIP = ntohl(payload.readUnsignedInt());
            int nVisitingESIPInt = (int)nVisitingESIP & 0xFFFFFFFF;
            byte[] byteVisitingESIP = ByteBuffer.allocate(4).putInt(nVisitingESIPInt).array();
            
            long nVisitingTargetHost = ntohl(payload.readUnsignedInt());
            int nVisitingTargetHostInt = (int)nVisitingTargetHost & 0xFFFFFFFF;
            byte[] byteVisitingTargetHostIP = ByteBuffer.allocate(4).putInt(nVisitingTargetHostInt).array();

            if(LMDHTServer.logging){
            	
	            String strVisitingESIP = String.format("%d.%d.%d.%d",(nVisitingESIP & 0xFF), (nVisitingESIP >> 8 & 0xFF), (nVisitingESIP >> 16 & 0xFF), (nVisitingESIP >> 24 & 0xFF));
	            String strVisitingTargetHostIP = String.format("%d.%d.%d.%d",(nVisitingTargetHost & 0xFF), (nVisitingTargetHost >> 8 & 0xFF), (nVisitingTargetHost >> 16 & 0xFF), (nVisitingTargetHost >> 24 & 0xFF));
	            
	            System.out.printf("[Node %d] Storing the pair: (Original Cnt IP=%s, New Ctn IP=%s, New Host IP=%s, New Edge Switch IP=%s)\n", LMDHTServer.nodeIndex, strHomeCTIP, strVisitingCTIP, strVisitingTargetHostIP, strVisitingESIP);
            }
            LMDHTServer.kserver.store(strHomeCTIP, strVisitingCTIP, byteVisitingCTIP, byteVisitingESIP, byteVisitingTargetHostIP, byteHomeCTIP);
            
            byte[] sendBuf = new byte[48];
            
            sendBuf[0] = OPCODE_NEW_APP;
            for (int i = 0;i < 4;i++){
                sendBuf[2 + (3-i)] = byteHomeCTIP[i];
                sendBuf[6 + (3-i)] = byteVisitingESIP[i];
                sendBuf[10 + (3-i)] = byteVisitingCTIP[i];
            }
            for (int i = 0;i < 2;i++){
            	sendBuf[14 + i] = (byte)0x00;
            }
            
			MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
			byte[] strDig = mDigest.digest(strHomeCTIP.getBytes());
            
			for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 170329
				sendBuf[16+i]=  strDig[i];
			}
			if(LMDHTServer.logging){
				System.out.println("Object ID: ");
			
				for (int i = 0;i < LM_HDR_LENGTH;i++){ 
					System.out.printf("%02x",(strDig[i]&0xff));
				}
				System.out.println();
			}
            
			for (int i = 0;i < LMDHTServer.swCount;i++){
				if (LMDHTServer.edgeSWList[i] != 0 && LMDHTServer.edgeSWList[i] != switchNum){
                    
                    byte[] swByte = ByteBuffer.allocate(2).putShort(LMDHTServer.edgeSWList[i]).array();
				    sendBuf[1] = swByte[1];
				    int swListIndex = LMDHTServer.edgeSWList[i]-1;
					if(LMDHTServer.logging)System.out.printf("receiving SW IP="+LMDHTServer.swIPAddrList[swListIndex]+",port="+LMDHTServer.ovsPort+"\n");

			        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
					clientCh.writeAndFlush(
    	                        new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress(LMDHTServer.swIPAddrList[swListIndex],LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
                }
			}
			byte[] swByte = ByteBuffer.allocate(2).putShort(switchNum).array();
			sendBuf[1] = swByte[1];
			if(LMDHTServer.logging)System.out.printf("receiving SW IP="+"127.0.0.1"+",port="+LMDHTServer.ovsPort+"\n");
			

	        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
			clientCh.writeAndFlush(
    	         new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress("127.0.0.1",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);

			
			/*
			for (int i = 0;i < 4;i++){
                sendBuf[2 + (3-i)] = byteVisitingCTIP[i];
                sendBuf[6 + (3-i)] = byteVisitingESIP[i];
                sendBuf[10 + (3-i)] = byteHomeCTIP[i];
            }
			strDig = mDigest.digest(strVisitingCTIP.getBytes());
			
			for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 170329
				sendBuf[16+i]=  strDig[i];
			}
			
			for (int i = 0;i < LMDHTServer.swCount;i++){
				byte[] swByte = ByteBuffer.allocate(2).putShort(LMDHTServer.edgeSWList[i]).array();
				sendBuf[1] = swByte[1];
				int swListIndex = LMDHTServer.edgeSWList[i]-1;
                
	
		        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();                
                clientCh.writeAndFlush(
    	                        new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress(LMDHTServer.swIPAddrList[swListIndex],LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
                
			}*/
        
            //---------------client example
//			String opCode = OPCODE_CTN_MOBILITY;
//			String swNum = "01"; 
//			String homeCtnIP = "0a000a03";
//			String newCtnIP = "0a000a03";
//			String newESIP = "0a001401";
//			String newHostIP = "0a001402";
//			String strInput = opCode+swNum+homeCtnIP+newCtnIP+newESIP+newHostIP; 
        
        } else if (opCode == OPCODE_GET_HASH){
        	if(LMDHTServer.logging)System.out.println("opCode 1: get Object ID from DHT server with digested IP");
        	//if(LMDHTServer.logging)System.out.println("opCode 6: get ip:port");

        	
            byte[] bytePortNumber = {payload.readByte(),payload.readByte()};
            String strPortNumber = ":"+((bytePortNumber[1] & 0xFF) + ((bytePortNumber[0] & 0xFF)*0x100));
            
        	MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
			byte[] strDig = mDigest.digest((strIP).getBytes());
            
            if(LMDHTServer.logging)System.out.printf("[Node %d] Getting the pair: (Host IP:Port Number=%s%s)\n", LMDHTServer.nodeIndex, strIP, strPortNumber);
            
            LMDHTServer.kserver.get(OPCODE_GET_HASH, strIP+strPortNumber, switchNum, byteHostIP, strDig);
        
            
            //---------------client example
//			String opCode = OPCODE_GET_HASH;
//			String swNum = "01"; 
//			String homeTargetHostIP = "0a000a02";
//			String portNumber = "0050";
//			String strInput = opCode+swNum+homeTargetHostIP+portNumber; 
        
        } else if (opCode == OPCODE_TOGGLE_LOGGING){
        	if(LMDHTServer.logging)System.out.println("opCode 101: Toggle ovs logging");
        	
        	byte[] sendBuf = new byte[2];
            
            sendBuf[0] = OPCODE_TOGGLE_LOGGING;
            for (int i = 0;i < LMDHTServer.swCount;i++){
				if (LMDHTServer.edgeSWList[i] != 0 && LMDHTServer.edgeSWList[i] != switchNum){
                    
                    byte[] swByte = ByteBuffer.allocate(2).putShort(LMDHTServer.edgeSWList[i]).array();
				    sendBuf[1] = swByte[1];
				    int swListIndex = LMDHTServer.edgeSWList[i]-1;
                    
	
			        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
				    clientCh.writeAndFlush(
    	                        new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress(LMDHTServer.swIPAddrList[swListIndex],LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
                } 
				
			}
			byte[] swByte = ByteBuffer.allocate(2).putShort(switchNum).array();
			sendBuf[1] = swByte[1];
			if(LMDHTServer.logging)System.out.printf("receiving SW IP="+"127.0.0.1"+",port="+LMDHTServer.ovsPort+"\n");

	        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
			
			clientCh.writeAndFlush(
    	         new DatagramPacket(Unpooled.copiedBuffer(sendBuf), new InetSocketAddress("127.0.0.1",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);  
            //---------------client example
//			String opCode = "OPCODE_TOGGLE_LOGGING";
//			String swNum = "01"; 
        
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
    }

}

@ChannelHandler.Sharable
class ClientHandler extends SimpleChannelInboundHandler<DatagramPacket> {
    @Override
    public void channelRead0(ChannelHandlerContext ctx, DatagramPacket msg) {
        if(LMDHTServer.logging)System.out.println("Must not be executed");
    }
}

/**
 * DHTServer
 * @author JaeheeHa
 * 
 * p2p key = Number160
 */
class DHTServer {
	
	private static final byte OPCODE_BOOTUP = 0;
    private static final byte OPCODE_GET_HASH = 1;
    private static final byte OPCODE_GET_IP = 2;
    private static final byte OPCODE_INFORM_CONNECTION = 3;
    private static final byte OPCODE_APP_MOBILITY = 4;
    private static final byte OPCODE_CTN_MOBILITY = 5;
    private static final byte OPCODE_GET_IPPORT = 6;
    
    private static final byte OPCODE_QUERIED_HASH = 1;
    private static final byte OPCODE_QUERIED_IP = 2;
    private static final byte OPCODE_UPDATE_IP = 3;
    private static final byte OPCODE_NEW_APP = 4;
    private static final byte OPCODE_NEW_CTN = 5;
    
    
    private static final int VISITING_IP = 1;
    private static final int ES_IP = 2;
    private static final int VISITING_TARGET_HOST = 3;
    private static final int HOME_TARGET_HOST = 4;
    private static final int HOME_IP = 5;
    
    private static final int LM_HDR_LENGTH = 32;
	
	private static Peer peer;
	
	public DHTServer(int peerId) throws Exception {
		Random rnd = new Random();
		Bindings b = new Bindings();
		peer = new PeerMaker(new Number160(rnd)).setPorts(LMDHTServer.ksvrPort).setBindings(b).makeAndListen();
		if(LMDHTServer.logging)System.out.println("My Peer ID = " + peer.getPeerID());
	}
	
	public DHTServer(int peerId, String mIP, int port) throws Exception {
		Random rnd = new Random();
		InetAddress address = Inet4Address.getByName(mIP);
		Bindings b = new Bindings();
		peer = new PeerMaker(new Number160(rnd)).setPorts(LMDHTServer.ksvrPort + peerId).setBindings(b).makeAndListen();
		FutureDiscover futureDiscover = peer.discover().setInetAddress(address)
				.setPorts(port).start();
		futureDiscover.awaitUninterruptibly();
		FutureBootstrap futureBootstrap = peer.bootstrap()
				.setInetAddress(address).setPorts(port).start();
		futureBootstrap.awaitUninterruptibly();
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

	public void get(final int opCode, final String input, final byte switchNum, final byte[] byteHostIP, final byte[] hashedIP) throws ClassNotFoundException, IOException, NoSuchAlgorithmException {	
		
		final Date date = new Date();
		final long starttime = date.getTime();
		
		if(opCode == OPCODE_GET_HASH){
			//In this case, input is a string of hostIP:port
			String strIP = input.split(":")[0];
			String firstSHA = sha256(strIP);
			FutureDHT futureDHT = peer.get(Number160.createHash(firstSHA)).start();
			futureDHT.addListener(new BaseFutureAdapter<FutureDHT>() {
				private byte lswitchNum = switchNum;
				private byte[] lbyteHostIP = byteHostIP.clone();
				private byte[] lhashedIP = hashedIP.clone();
				@Override
				public void operationComplete(FutureDHT future)
						throws Exception {
					if (future.isSuccess()) {
						//Jaehyun implements sending UDP packet to OVS
						if(LMDHTServer.logging)System.out.println("OpCode = "+OPCODE_GET_HASH+", " + future.getData().getObject().toString());
						String foundData = future.getData().getObject().toString();
						
						JsonParser parser = new JsonParser();
						JsonObject jobj = new JsonObject();
						jobj = (JsonObject) parser.parse(foundData);
						
						String recvData = jobj.get(VISITING_IP+"").getAsString() + jobj.get(ES_IP+"").getAsString();
						
						byte[] sendData = new byte[43];//Jaehee modified 160720
						
						sendData[0] = OPCODE_QUERIED_HASH;
						sendData[1] = lswitchNum;
						for (int i = 0; i < 4;i++){
							sendData[2+(3-i)] = (byte) ((Character.digit(recvData.charAt(i*2), 16) << 4) + Character.digit(recvData.charAt(i*2+1), 16));
							sendData[6+LM_HDR_LENGTH+(3-i)] = (byte) ((Character.digit(recvData.charAt((i+4)*2), 16) << 4) + Character.digit(recvData.charAt((i+4)*2+1), 16));
						}//Jaehee modified 160720
						for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 160720
							sendData[6+i]=  lhashedIP[i];
						}
						sendData[42]='\0';


				        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
						clientCh.writeAndFlush(
							new DatagramPacket(Unpooled.copiedBuffer(sendData), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
				
						if(LMDHTServer.logging) {
							System.out.println("send oid:");
							for (int i = 0 ; i < LM_HDR_LENGTH ; i++) {
								System.out.printf("%02x",sendData[6+i]);
							}
							System.out.println();
						}
						if(LMDHTServer.logFileOut)
						{
							Date enddate = new Date();
							long endtime = enddate.getTime();
							long diff = endtime-starttime;
							
							String fileName = "/DHTGetDelay.log";
							fileName = System.getProperty("user.dir")+fileName.trim();
					        File file = new File (fileName);
							
					        FileWriter fw = null;
			        	    BufferedWriter bw = null;
			        	    PrintWriter out = null;
					        try{
					        	fw = new FileWriter(file, true);
				        	    bw = new BufferedWriter(fw);
				        	    out = new PrintWriter(bw);
				        	
				        	    out.println(diff);
				        	    
				        	} catch (IOException e) {
					        	    //exception handling left as an exercise for the reader
					        } finally {
					        	if (out != null) {
					        		out.close();
					        	}
					        	if (bw != null) {
					        		bw.close();
					        	}
					        	if (fw != null) {
					        		fw.close();
					        	}
					        }
						}
					} else {
						if(LMDHTServer.logging)System.out.println("Get Failed");
						
						byte[] firstSHA = sha256(input).getBytes();
						LMDHTServer.kserver.get(OPCODE_GET_IPPORT, input, switchNum, lbyteHostIP, firstSHA);

						if(LMDHTServer.logFileOut) {
							
							Date enddate = new Date();
							long endtime = enddate.getTime();
							long diff = endtime-starttime;
							
							String fileName = "/DHTGetDelay.log";
							fileName = System.getProperty("user.dir")+fileName.trim();
					        File file = new File (fileName);
							
					        FileWriter fw = null;
			        	    BufferedWriter bw = null;
			        	    PrintWriter out = null;
					        try{
					        	fw = new FileWriter(file, true);
				        	    bw = new BufferedWriter(fw);
				        	    out = new PrintWriter(bw);
				        	
				        	    out.println(diff);
				        	    
				        	} catch (IOException e) {
					        	    //exception handling left as an exercise for the reader
					        } finally {
					        	if (out != null) {
					        		out.close();
					        	}
					        	if (bw != null) {
					        		bw.close();
					        	}
					        	if (fw != null) {
					        		fw.close();
					        	}
					        }
					        
						}
					}

				}
			});
		} else if(opCode == OPCODE_GET_IP){
			//In this case, input is an objectKey
			FutureDHT futureDHT = peer.get(Number160.createHash(input)).start();
			futureDHT.addListener(new BaseFutureAdapter<FutureDHT>() {
				@Override
				public void operationComplete(FutureDHT future)
						throws Exception {
					if (future.isSuccess()) {
						//Jaehyun needs to implement sending UDP packet to OVS
						if(LMDHTServer.logging)System.out.println("OpCode = "+OPCODE_GET_IP+", " + future.getData().getObject().toString());
						String foundData = future.getData().getObject().toString();
						
						JsonObject jobj = new JsonObject();
						jobj = (JsonObject) new JsonParser().parse(foundData);
						
						String recvData = jobj.get(VISITING_IP+"").getAsString() + jobj.get(ES_IP+"").getAsString();
						
						byte[] sendData = new byte[43];//Jaehee modified 160720
						
						sendData[0] = OPCODE_QUERIED_IP;
						sendData[1] = switchNum;
						for (int i = 0; i < 4;i++){
							sendData[2+(3-i)] = (byte) ((Character.digit(recvData.charAt(i*2), 16) << 4) + Character.digit(recvData.charAt(i*2+1), 16));
							sendData[6+LM_HDR_LENGTH+(3-i)] = (byte) ((Character.digit(recvData.charAt((i+4)*2), 16) << 4) + Character.digit(recvData.charAt((i+4)*2+1), 16));

						}//Jaehee modified 160720
						for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 160720
							sendData[6+i]=  hashedIP[i];
						}
						
						sendData[42]= '\0';

				        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
						clientCh.writeAndFlush(
							new DatagramPacket(Unpooled.copiedBuffer(sendData), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);

						if(LMDHTServer.logging) {
							System.out.println("send oid:");
							for (int i = 0 ; i < LM_HDR_LENGTH ; i++) {
								System.out.printf("%02x",sendData[6+i]);
							}
							System.out.println();
						}
						if (LMDHTServer.logFileOut) {
							Date enddate = new Date();
							long endtime = enddate.getTime();
							long diff = endtime-starttime;
							
							String fileName = "/DHTGetDelay.log";
							fileName = System.getProperty("user.dir")+fileName.trim();
					        File file = new File (fileName);
							
					        FileWriter fw = null;
			        	    BufferedWriter bw = null;
			        	    PrintWriter out = null;
					        try{
					        	fw = new FileWriter(file, true);
				        	    bw = new BufferedWriter(fw);
				        	    out = new PrintWriter(bw);
				        	
				        	    out.println(diff);
				        	    
				        	} catch (IOException e) {
					        	    //exception handling left as an exercise for the reader
					        } finally {
					        	if (out != null) {
					        		out.close();
					        	}
					        	if (bw != null) {
					        		bw.close();
					        	}
					        	if (fw != null) {
					        		fw.close();
					        	}
					        }
						}
					} else {
						if(LMDHTServer.logging)System.out.println("Get Failed");
						
						byte[] sendData = new byte[43];//Jaehee modified 160720
						
						sendData[0] = OPCODE_QUERIED_IP;
						sendData[1] = switchNum;
						for (int i = 0; i < 4;i++){
							sendData[2+(3-i)] = byteHostIP[i];
							sendData[6+LM_HDR_LENGTH+i] = 0x00;
						}//Jaehee modified 160720
						for (int i = 0; i < LM_HDR_LENGTH;i++){ //Jaehee modified 160720
							sendData[6+i]=  hashedIP[i];
						}
						
						sendData[42]='\0';


				        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
						clientCh.writeAndFlush(
				                        new DatagramPacket(Unpooled.copiedBuffer(sendData), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);

						if(LMDHTServer.logging) {
							System.out.println("send oid:");
							for (int i = 0 ; i < LM_HDR_LENGTH ; i++) {
								System.out.printf("%02x",sendData[6+i]);
							}
							System.out.println();
							
						}
						if(LMDHTServer.logFileOut) {
							Date enddate = new Date();
							long endtime = enddate.getTime();
							long diff = endtime-starttime;
						
							String fileName = "/DHTGetDelay.log";
							fileName = System.getProperty("user.dir")+fileName.trim();
					        File file = new File (fileName);
							
					        FileWriter fw = null;
			        	    BufferedWriter bw = null;
			        	    PrintWriter out = null;
					        try{
					        	fw = new FileWriter(file, true);
				        	    bw = new BufferedWriter(fw);
				        	    out = new PrintWriter(bw);
				        	
				        	    out.println(diff);
				        	    
				        	} catch (IOException e) {
					        	    //exception handling left as an exercise for the reader
					        } finally {
					        	if (out != null) {
					        		out.close();
					        	}
					        	if (bw != null) {
					        		bw.close();
					        	}
					        	if (fw != null) {
					        		fw.close();
					        	}
					        }
						}
					}

				}
			});
		} else if(opCode == OPCODE_GET_IPPORT){
			//In this case, input is a string of hostIP:Port Number
			
			String firstSHA = sha256(input);
			FutureDHT futureDHT = peer.get(Number160.createHash(firstSHA)).start();
			futureDHT.addListener(new BaseFutureAdapter<FutureDHT>() {
				private byte lswitchNum = switchNum;
				private byte[] lbyteHostIP = byteHostIP.clone();
				private byte[] lhashedIP = hashedIP.clone();
				@Override
				public void operationComplete(FutureDHT future)
						throws Exception {
					if (future.isSuccess()) {
						//Jaehyun implements sending UDP packet to OVS
						if(LMDHTServer.logging)System.out.println("OpCode = "+OPCODE_GET_IPPORT+", " + future.getData().getObject().toString());
						String foundData = future.getData().getObject().toString();
						int nPort = Integer.parseInt(input.split(":")[1]);
						String strPort = Integer.toHexString(nPort);
						
						switch (4-strPort.length()){
						case 4 : strPort = "0000";
								break; 
						case 3 : strPort = "000"+strPort;
								break;
						case 2 : strPort = "00"+strPort;
								break;
						case 1 : strPort = "0"+strPort;
								break;
						}
						
						JsonParser parser = new JsonParser();
						JsonObject jobj = new JsonObject();
						
						
						jobj = (JsonObject) parser.parse(foundData);
						String recvData = jobj.get(HOME_TARGET_HOST+"").getAsString() + jobj.get(ES_IP+"").getAsString() + jobj.get(VISITING_IP+"").getAsString() + strPort;

						byte[] sendData = new byte[49];//Jaehee modified 160720
						
						sendData[0] = OPCODE_NEW_APP;
						sendData[1] = lswitchNum;
						for (int i = 0; i < 4;i++){
							sendData[2+(3-i)] = (byte) ((Character.digit(recvData.charAt(i*2), 16) << 4) + Character.digit(recvData.charAt(i*2+1), 16)); //HOME_TARGET_HOST
							sendData[6+(3-i)] = (byte) ((Character.digit(recvData.charAt((i+4)*2), 16) << 4) + Character.digit(recvData.charAt((i+4)*2+1), 16)); //ES_IP
							sendData[10+(3-i)] = (byte) ((Character.digit(recvData.charAt((i+8)*2), 16) << 4) + Character.digit(recvData.charAt((i+8)*2+1), 16)); //VISITING_IP
						}//Jaehee modified 160720

						for (int i = 0; i < 2;i++){
							sendData[14+i] = (byte) ((Character.digit(recvData.charAt((i+12)*2), 16) << 4) + Character.digit(recvData.charAt((i+12)*2+1), 16)); //strPort
						}
						for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 160720
							sendData[16+i]=  lhashedIP[i];
						}

						sendData[48]='\0';

				        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
						clientCh.writeAndFlush(
							new DatagramPacket(Unpooled.copiedBuffer(sendData), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
						
						
						if(LMDHTServer.logging) {
							System.out.println("send oid:");
							for (int i = 0 ; i < LM_HDR_LENGTH ; i++) {
								System.out.printf("%02x",sendData[16+i]);
							}
							System.out.println();
						}
						if(LMDHTServer.logFileOut) {
							Date enddate = new Date();
							long endtime = enddate.getTime();
							long diff = endtime-starttime;
							
							String fileName = "/DHTGetDelay.log";
							fileName = System.getProperty("user.dir")+fileName.trim();
					        File file = new File (fileName);
							
					        FileWriter fw = null;
			        	    BufferedWriter bw = null;
			        	    PrintWriter out = null;
					        try{
					        	fw = new FileWriter(file, true);
				        	    bw = new BufferedWriter(fw);
				        	    out = new PrintWriter(bw);
				        	
				        	    out.println(diff);
				        	    
				        	} catch (IOException e) {
					        	    //exception handling left as an exercise for the reader
					        } finally {
					        	if (out != null) {
					        		out.close();
					        	}
					        	if (bw != null) {
					        		bw.close();
					        	}
					        	if (fw != null) {
					        		fw.close();
					        	}
					        }
						}
					} /*else {
						
						byte[] sendData = new byte[42];//Jaehee modified 160720
						
						sendData[0] = OPCODE_QUERIED_HASH;
						sendData[1] = switchNum;
						for (int i = 0; i < 4;i++){
							sendData[2+(3-i)] = byteHostIP[i];
							sendData[38+i] = 0x00;
						}//Jaehee modified 160720
						for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 160720
							sendData[6+i]=  hashedIP[i];
						}

				        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
						clientCh.writeAndFlush(
				                        new DatagramPacket(Unpooled.copiedBuffer(sendData), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
						
						if(LMDHTServer.logging)System.out.println("Get Failed");
					}*/
					
					
					
					
					else {
						if(LMDHTServer.logging)System.out.println("Get Failed");
						
						int nPort = Integer.parseInt(input.split(":")[1]);
						String strPort = Integer.toHexString(nPort);
						
						switch (4-strPort.length()){
						case 4 : strPort = "0000";
								break; 
						case 3 : strPort = "000"+strPort;
								break;
						case 2 : strPort = "00"+strPort;
								break;
						case 1 : strPort = "0"+strPort;
								break;
						}
						byte[] sendData = new byte[49];//Jaehee modified 160720
						
						sendData[0] = OPCODE_NEW_APP;
						sendData[1] = switchNum;
						for (int i = 0; i < 4;i++){
							sendData[2+(3-i)] = byteHostIP[i];
							sendData[6+i] = 0x00;
							sendData[10+(3-i)] = byteHostIP[i];
						}//Jaehee modified 170329
						for (int i = 0; i < 2;i++){
							sendData[14+i] = (byte) ((Character.digit(strPort.charAt(i*2), 16) << 4) + Character.digit(strPort.charAt(i*2+1), 16)); //strPort

						}

						for (int i = 0; i < LM_HDR_LENGTH;i++){ //Jaehee modified 160720
							sendData[16+i]=  hashedIP[i];
						}
						
						sendData[48]='\0';

				        Channel clientCh = LMDHTServer.bClient.bind(0).sync().channel();
						clientCh.writeAndFlush(
				                        new DatagramPacket(Unpooled.copiedBuffer(sendData), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);


						
						if(LMDHTServer.logging) {
							System.out.println("send oid:");
							for (int i = 0 ; i < LM_HDR_LENGTH ; i++) {
								System.out.printf("%02x",sendData[16+i]);
							}
							System.out.println();
						}
						if(LMDHTServer.logFileOut) {
							Date enddate = new Date();
							long endtime = enddate.getTime();
							long diff = endtime-starttime;
							
							String fileName = "/DHTGetDelay.log";
							fileName = System.getProperty("user.dir")+fileName.trim();
					        File file = new File (fileName);
							
					        FileWriter fw = null;
			        	    BufferedWriter bw = null;
			        	    PrintWriter out = null;
					        try{
					        	fw = new FileWriter(file, true);
				        	    bw = new BufferedWriter(fw);
				        	    out = new PrintWriter(bw);
				        	
				        	    out.println(diff);
				        	    
				        	} catch (IOException e) {
					        	    //exception handling left as an exercise for the reader
					        } finally {
					        	if (out != null) {
					        		out.close();
					        	}
					        	if (bw != null) {
					        		bw.close();
					        	}
					        	if (fw != null) {
					        		fw.close();
					        	}
					        }
						}
					}

				}
			});
		} else {
			if(LMDHTServer.logging)System.out.println("Logical Error");
		}
	}
	
	public void store(String strHostIP, byte[] hostIP, byte[] switchIP) throws IOException, NoSuchAlgorithmException {
		//opCode == OPCODE_INFORM_CONNECTION
		
		StringBuilder jsonString = new StringBuilder();
		String strData = "";
		for(int i=0; i < hostIP.length ;i++)
			strData += String.format("%02x", hostIP[i]);
		
		
		jsonString.append("{ \"" + VISITING_IP + "\" : \"" + strData + "\",");
		
		
		strData = "";
		for(int i=0; i < switchIP.length; i++)
			strData += String.format("%02x", switchIP[i]);
		
		jsonString.append("\""+ES_IP+"\" : \""+ strData +"\" }");
		
		
		String firstSHA = sha256(strHostIP);

		if(LMDHTServer.logging)System.out.println("key: "+Number160.createHash(firstSHA)+", data: "+jsonString.toString());
		peer.put(Number160.createHash(firstSHA)).setData(new Data(jsonString.toString())).start();
	}
	
	public void store(String originalHostIPPort, String visitingTargetHostIPPort, byte[] visitingTargetHostIP, byte[] switchIP, byte[] homeTargetHostIP) throws IOException, NoSuchAlgorithmException {
		//opCode == OPCODE_APP_MOBILITY
		
		StringBuilder jsonString = new StringBuilder();
		
		String strData = "";
		for(int i=0; i < visitingTargetHostIP.length ;i++)
			strData += String.format("%02x", visitingTargetHostIP[i]);
		
		jsonString.append("{ \"" + VISITING_IP + "\" : \"" + strData + "\",");
		
		strData = "";
		for(int i=0; i < switchIP.length ;i++)
			strData += String.format("%02x", switchIP[i]);
		jsonString.append("\""+ES_IP+"\" : \""+ strData +"\",");
		
		strData = "";
		for(int i=0; i < homeTargetHostIP.length ;i++)
			strData += String.format("%02x", homeTargetHostIP[i]);
		jsonString.append("\""+HOME_TARGET_HOST+"\" : \""+ strData +"\" }");
		
		
		String firstSHA = sha256(originalHostIPPort);
		
		if(LMDHTServer.logging)System.out.println("key: "+Number160.createHash(firstSHA)+", data: "+jsonString.toString());
		peer.put(Number160.createHash(firstSHA)).setData(new Data(jsonString.toString())).start();
		
		
		String firstSHA_2 = sha256(visitingTargetHostIPPort);
		/*StringBuilder jsonString2 = new StringBuilder();
		
		
		strData = "";
		for(int i=0; i < visitingTargetHostIP.length ;i++)
			strData += String.format("%02x", visitingTargetHostIP[i]);
		jsonString2.append("{ \"" + VISITING_IP + "\" : \"" + strData + "\",");

		strData = "";
		for(int i=0; i < switchIP.length ;i++)
			strData += String.format("%02x", switchIP[i]);
		jsonString2.append("\""+ES_IP+"\" : \""+ strData +"\",");

		strData = "";
		for(int i=0; i < homeTargetHostIP.length ;i++)
			strData += String.format("%02x", homeTargetHostIP[i]);
		jsonString2.append("\""+HOME_TARGET_HOST+"\" : \""+ strData +"\" }");*/
		
		if(LMDHTServer.logging)System.out.println("key: "+Number160.createHash(firstSHA_2)+", data: "+jsonString.toString());
		peer.put(Number160.createHash(firstSHA_2)).setData(new Data(jsonString.toString())).start();
		jsonString.setLength(0);
		//jsonString2.setLength(0);
	}
	
	public void store(String strHomeCTIP, String strSwitchedIP, byte[] visitingCtnIP, byte[] switchIP, byte[] visitingTargetHostIP, byte[] homeCtnIP) throws IOException, NoSuchAlgorithmException {
		//opCode == OPCODE_CTN_MOBILITY
		
		StringBuilder jsonString = new StringBuilder();
		
		String strData = "";
		for(int i=0; i < visitingCtnIP.length ;i++)
			strData += String.format("%02x", visitingCtnIP[i]);
		jsonString.append("{ \"" + VISITING_IP + "\" : \"" + strData + "\",");

		strData = "";
		for(int i=0; i < switchIP.length ;i++)
			strData += String.format("%02x", switchIP[i]);
		jsonString.append("\""+ES_IP+"\" : \""+ strData +"\",");

		strData = "";
		for(int i=0; i < homeCtnIP.length ;i++)
			strData += String.format("%02x", homeCtnIP[i]);
		jsonString.append("\""+HOME_IP+"\" : \""+ strData +"\",");
	
		strData = "";
		for(int i=0; i < visitingTargetHostIP.length ;i++)
			strData += String.format("%02x", visitingTargetHostIP[i]);
		jsonString.append("\""+VISITING_TARGET_HOST+"\" : \""+ strData +"\" }");

		
		String firstSHA = sha256(strHomeCTIP);
		
		if(LMDHTServer.logging)System.out.println("key: "+Number160.createHash(firstSHA)+", data: "+jsonString.toString());
		peer.put(Number160.createHash(firstSHA)).setData(new Data(jsonString.toString())).start();
		
		
		
		/*strData = "";
		for(int i=0; i < visitingCtnIP.length ;i++)
			strData += String.format("%02x", visitingCtnIP[i]);
		jobj2.put(VISITING_IP+"", strData);
		strData = "";
		for(int i=0; i < switchIP.length ;i++)
			strData += String.format("%02x", switchIP[i]);
		jobj2.put(ES_IP+"", strData);
		strData = "";
		for(int i=0; i < homeCtnIP.length ;i++)
			strData += String.format("%02x", homeCtnIP[i]);
		jobj2.put(HOME_IP+"", strData);
		strData = "";
		for(int i=0; i < visitingTargetHostIP.length ;i++)
			strData += String.format("%02x", visitingTargetHostIP[i]);
		jobj2.put(VISITING_TARGET_HOST+"", strData);*/
		
		String firstSHA_2 = sha256(strSwitchedIP);
		
		if(LMDHTServer.logging)System.out.println("key: "+Number160.createHash(firstSHA_2)+", data: "+jsonString.toString());
		peer.put(Number160.createHash(firstSHA_2)).setData(new Data(jsonString.toString())).start();
		jsonString.setLength(0);
	}
	/*
	public void store(String strHostIP, byte[] hostIP, byte[] switchIP) throws IOException, NoSuchAlgorithmException {
		//opCode == OPCODE_APP_MOBILITY
		String strData = "";
		for(int i=0; i < hostIP.length ;i++)
			strData = strData + String.format("%02x", hostIP[i]);
		for(int i=0; i < switchIP.length; i++)
			strData = strData + String.format("%02x", switchIP[i]);
		String firstSHA = sha256(strHostIP);
		peer.put(Number160.createHash(firstSHA)).setData(new Data(strData)).start();
	}
	
	public void store(String strHostIP, byte[] hostIP, byte[] switchIP) throws IOException, NoSuchAlgorithmException {
		//opCode == OPCODE_CTN_MOBILITY
		String strData = "";
		for(int i=0; i < hostIP.length ;i++)
			strData = strData + String.format("%02x", hostIP[i]);
		for(int i=0; i < switchIP.length; i++)
			strData = strData + String.format("%02x", switchIP[i]);
		String firstSHA = sha256(strHostIP);
		peer.put(Number160.createHash(firstSHA)).setData(new Data(strData)).start();
	}*/
	
	//backup
	/*
	public void get(final int opCode, final String input, final byte switchNum, final byte[] byte_host_ip, final byte[] hashedIP) throws ClassNotFoundException, IOException, NoSuchAlgorithmException {
		
		
		
		if(opCode == LMDHTServerHandler.OPCODE_GET_HASH){
			//In this case, input is a string of hostIP
			String firstSHA = sha256(input);
			FutureDHT futureDHT = peer.get(Number160.createHash(firstSHA)).start();
			futureDHT.addListener(new BaseFutureAdapter<FutureDHT>() {
				private byte lswitchNum = switchNum;
				private byte[] lbyte_host_ip = byte_host_ip.clone();
				private byte[] lhashedIP = hashedIP.clone();
				@Override
				public void operationComplete(FutureDHT future)
						throws Exception {
					if (future.isSuccess()) {
						//Jaehyun implements sending UDP packet to OVS
						if(LMDHTServer.logging)System.out.println("OpCode = "+LMDHTServerHandler.OPCODE_GET_HASH+", " + future.getData().getObject().toString());
						String recv_data = future.getData().getObject().toString();
						byte[] send_data = new byte[42];//Jaehee modified 160720
						
						send_data[0] = 0x01; //OPCODE_GET_HASH
						send_data[1] = lswitchNum;
						for (int i = 0; i < 4;i++){
							send_data[2+(3-i)] = (byte) ((Character.digit(recv_data.charAt(i*2), 16) << 4) + Character.digit(recv_data.charAt(i*2+1), 16));
							send_data[26+i] = (byte) ((Character.digit(recv_data.charAt((i+4)*2), 16) << 4) + Character.digit(recv_data.charAt((i+4)*2+1), 16));
						}
						for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 160720
							send_data[6+i]=  hashedIP[i];
						}


						LMDHTServer.client_ch.writeAndFlush(
							new DatagramPacket(Unpooled.copiedBuffer(send_data), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);
				
					} else {
						byte[] send_data = new byte[42];//Jaehee modified 160720
						
						send_data[0] = 0x01;
						send_data[1] = switchNum;
						for (int i = 0; i < 4;i++){
							send_data[2+(3-i)] = byte_host_ip[i];
							send_data[26+i] = 0x00;
						}
						for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 160720
							send_data[6+i]=  hashedIP[i];
						}
						LMDHTServer.client_ch.writeAndFlush(
				                        new DatagramPacket(Unpooled.copiedBuffer(send_data), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);


						if(LMDHTServer.logging)System.out.println("Get Failed");
						
					}

				}
			});
		} else if(opCode == LMDHTServerHandler.OPCODE_GET_IP){
			//In this case, input is an objectKey
			FutureDHT futureDHT = peer.get(Number160.createHash(input)).start();
			futureDHT.addListener(new BaseFutureAdapter<FutureDHT>() {
				@Override
				public void operationComplete(FutureDHT future)
						throws Exception {
					if (future.isSuccess()) {
						//Jaehyun needs to implement sending UDP packet to OVS
						if(LMDHTServer.logging)System.out.println("OpCode = "+LMDHTServerHandler.OPCODE_GET_IP+", " + future.getData().getObject().toString());
						String recv_data = future.getData().getObject().toString();
						byte[] send_data = new byte[42];//Jaehee modified 160720
						
						send_data[0] = 0x02; //OPCODE_GET_IP
						send_data[1] = switchNum;
						for (int i = 0; i < 4;i++){
							send_data[2+(3-i)] = (byte) ((Character.digit(recv_data.charAt(i*2), 16) << 4) + Character.digit(recv_data.charAt(i*2+1), 16));
							send_data[26+i] = (byte) ((Character.digit(recv_data.charAt((i+4)*2), 16) << 4) + Character.digit(recv_data.charAt((i+4)*2+1), 16));

						}
						for (int i = 0; i < LM_HDR_LENGTH;i++){//Jaehee modified 160720
							send_data[6+i]=  hashedIP[i];
						}

						LMDHTServer.client_ch.writeAndFlush(
							new DatagramPacket(Unpooled.copiedBuffer(send_data), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);

					} else {
						byte[] send_data = new byte[42];//Jaehee modified 160720
						
						send_data[0] = 0x02;
						send_data[1] = switchNum;
						for (int i = 0; i < 4;i++){
							send_data[2+(3-i)] = byte_host_ip[i];
							send_data[26+i] = 0x00;
						}
						for (int i = 0; i < LM_HDR_LENGTH;i++){ //Jaehee modified 160720
							send_data[6+i]=  hashedIP[i];
						}
						LMDHTServer.client_ch.writeAndFlush(
				                        new DatagramPacket(Unpooled.copiedBuffer(send_data), new InetSocketAddress("localhost",LMDHTServer.ovsPort))).addListener(ChannelFutureListener.CLOSE);


						if(LMDHTServer.logging)System.out.println("Get Failed");
					}

				}
			});
		} else {
			if(LMDHTServer.logging)System.out.println("Logical Error");
		}
	}*/
	
	//backup
	/*
	public void store(String strHostIP, byte[] hostIP, byte[] switchIP) throws IOException, NoSuchAlgorithmException {
		//opCode == OPCODE_INFORM_CONNECTION
		String strData = "";
		for(int i=0; i < hostIP.length ;i++)
			strData = strData + String.format("%02x", hostIP[i]);
		for(int i=0; i < switchIP.length; i++)
			strData = strData + String.format("%02x", switchIP[i]);
		String firstSHA = sha256(strHostIP);
		peer.put(Number160.createHash(firstSHA)).setData(new Data(strData)).start();
	}*/
}

