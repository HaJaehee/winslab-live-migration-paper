import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.Random;

import net.tomp2p.connection.Bindings;
import net.tomp2p.futures.BaseFutureAdapter;
import net.tomp2p.futures.FutureBootstrap;
import net.tomp2p.futures.FutureDHT;
import net.tomp2p.futures.FutureDiscover;
import net.tomp2p.p2p.Peer;
import net.tomp2p.p2p.PeerMaker;
import net.tomp2p.peers.Number160;
import net.tomp2p.peers.Number480;
import net.tomp2p.storage.Data;



public class DHTTest {
	public static int PEER_NUM = 1;
	public static String myIPAddr = "10.0.20.1";
	public static String mySubNet = "10.16.";
	private static Peer peer;
	private static Peer[] peers;
	public static int ksvrPort = 8468; 
	public static boolean logging = true;
	public DHTTest(int peerId) throws Exception {
		Random rnd = new Random();
		Bindings b = new Bindings();
		if(DHTTest.logging)System.out.println("myPeerId : " + peerId);
		peer = new PeerMaker(new Number160(rnd)).setPorts(DHTTest.ksvrPort).setBindings(b).makeAndListen();
		//peer.getStoreRPC().getPeerBean().getReplicationStorage().setReplicationFactor(3);
		if(DHTTest.logging)System.out.println("replication factor: " + peer.getStoreRPC().getPeerBean().getReplicationStorage().getReplicationFactor());
		peers = new Peer[PEER_NUM];
		Thread.sleep(100);	
		for (int i = 0; i < PEER_NUM-1;i++){
			Bindings bi = new Bindings();
			InetAddress addressi = Inet4Address.getByName(myIPAddr);
			peers[i] = new PeerMaker(new Number160(new Random())).setPorts(20000 + peerId * 100 + i).setBindings(bi).makeAndListen();
			//peers[i].getStoreRPC().getPeerBean().getReplicationStorage().setReplicationFactor(3);
			FutureDiscover futureDiscoveri = peers[i].discover().setInetAddress(addressi)
                                .setPorts(DHTTest.ksvrPort + peerId).start();
	                futureDiscoveri.awaitUninterruptibly();
        	        FutureBootstrap futureBootstrapi = peers[i].bootstrap()
                                .setInetAddress(addressi).setPorts(DHTTest.ksvrPort + peerId).start();
               	 	futureBootstrapi.awaitUninterruptibly();
		}
	}
	
	public DHTTest(int peerId, String mIP, int port) throws Exception {
		Random rnd = new Random();
		InetAddress address = Inet4Address.getByName(mIP);
		Bindings b = new Bindings();
		//Number160 myPeerId = new Number160(2);
		if(DHTTest.logging)System.out.println("myPeerId : " + peerId);

		peer = new PeerMaker(new Number160(rnd)).setPorts(DHTTest.ksvrPort + peerId).setBindings(b).makeAndListen();
		FutureDiscover futureDiscover = peer.discover().setInetAddress(address)
				.setPorts(port).start();
		futureDiscover.awaitUninterruptibly();
		FutureBootstrap futureBootstrap = peer.bootstrap()
				.setInetAddress(address).setPorts(port).start();
		futureBootstrap.awaitUninterruptibly();
		peers = new Peer[PEER_NUM];
		Thread.sleep(100);
                for (int i = 0; i < PEER_NUM-1;i++){
                        Bindings bi = new Bindings();
                        InetAddress addressi = Inet4Address.getByName(myIPAddr);
                        peers[i] = new PeerMaker(new Number160(new Random())).setPorts(20000 + peerId * 100 + i).setBindings(bi).makeAndListen();
                        FutureDiscover futureDiscoveri = peers[i].discover().setInetAddress(addressi)
                                .setPorts(DHTTest.ksvrPort + peerId).start();
                        futureDiscoveri.awaitUninterruptibly();
                        FutureBootstrap futureBootstrapi = peers[i].bootstrap()
                                .setInetAddress(addressi).setPorts(DHTTest.ksvrPort + peerId).start();
                        futureBootstrapi.awaitUninterruptibly();
                }
	
	}

	
	static String sha1(String input) throws NoSuchAlgorithmException {
		MessageDigest mDigest = MessageDigest.getInstance("SHA1");
		byte[] result = mDigest.digest(input.getBytes());
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < result.length; i++) {
			sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return sb.toString();
	}
	

	public static void main(String args[]) throws Exception {
		DHTTest kserver = null;
		if (args.length == 1){
			kserver = new DHTTest(Integer.parseInt(args[0]));
		}else if (args.length == 3){
			kserver = new DHTTest(Integer.parseInt(args[0]), args[1], Integer.parseInt(args[2]));
		}else{
			if(DHTTest.logging)System.out.println("Usage: [my port] ([bootstrap ip] [bootstrap port])");
			System.exit(1);
		}
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("boot strapping done press enter: ");
		String keyinput1 = in.readLine();
		HashMap<Number160, Integer> hm = new HashMap<Number160, Integer>();
		int cnt1=0;
		int cnt2=2;
		for (int i = 0; i < 20000;i++){
			String cip;
			cip = mySubNet + cnt1 + "." + cnt2; 
			cnt2++;
			if(cnt2==256){
				cnt2 = 1;
				cnt1++;
			}
			kserver.store(cip, "value");
			Thread.sleep(40);
		}
		cnt1=0;
		cnt2=2;
		Thread.sleep(10000);
		System.out.print("storing done press enter: ");
		String keyinput2 = in.readLine();
		kserver.peers[PEER_NUM-1] = kserver.peer;
		BufferedWriter out = new BufferedWriter(new FileWriter("out.txt"));
		BufferedWriter out2 = new BufferedWriter(new FileWriter("out2.txt"));
		for (int i = 0; i < PEER_NUM;i++){
			NavigableMap<Number480, Data> tmp = kserver.peers[i].getStoreRPC()
					.getPeerBean().getStorage().map();
			int cnt = 0;
			for (Entry<Number480, Data> element : tmp.entrySet()) {
				cnt++;
				if (hm.containsKey(element.getKey().getLocationKey())){
					int count = hm.get(element.getKey().getLocationKey());
					count++;
					hm.put(element.getKey().getLocationKey(), count);
				}else{
					hm.put(element.getKey().getLocationKey(), 1);
				}
			}
			out.write("" + i + ", " + cnt); out.newLine();
		}
		int hashCnt = 0;
		for (Number160 hi : hm.keySet()){
			out2.write("key : " + hi + " value : " + hm.get(hi)); out2.newLine();
			hashCnt++;
		}
		out2.write("hashmap count : " + hashCnt); out2.newLine();
		out.close();
		out2.close();
		
		if(DHTTest.logging)System.out.println("Done");					
		
	}

	public void store(String input, String value) throws IOException, NoSuchAlgorithmException {
		peer.put(Number160.createHash(input)).setData(new Data(value)).start();
	}
}
