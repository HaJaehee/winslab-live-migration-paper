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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.lang.Integer;

public class InsertEntry {
	public static int PEER_NUM = 1;
	private static Peer peer;
	public static int ksvrPort = 8468;
	public InsertEntry(int peerId, String mIP, int port) throws Exception {
		Random rnd = new Random();
		InetAddress address = Inet4Address.getByName(mIP);
		Bindings b = new Bindings();

		peer = new PeerMaker(new Number160(rnd)).setPorts(InsertEntry.ksvrPort + peerId).setBindings(b).makeAndListen();
		FutureDiscover futureDiscover = peer.discover().setInetAddress(address)
				.setPorts(port).start();
		futureDiscover.awaitUninterruptibly();
		FutureBootstrap futureBootstrap = peer.bootstrap()
				.setInetAddress(address).setPorts(port).start();
		futureBootstrap.awaitUninterruptibly();
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
	
	public static String getCurrentTimeMilli(){
		SimpleDateFormat myFormat = new SimpleDateFormat("HH:mm:ss.SSS");
                Date now = new Date();
                String strDate = myFormat.format(now);
		
		return strDate;
	}
	public static void main(String args[]) throws Exception {
		InsertEntry kserver = null;
		kserver = new InsertEntry(1, "10.0.10.1", InsertEntry.ksvrPort);
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		while(true){
			System.out.print("boot strapping done. input subnet digit [0-9] : ");

			String keyinput1 = in.readLine();	
			int subnetDigit=Integer.parseInt(keyinput1);
			System.out.println("input division ratio [1-100] : ");
			System.out.println("3로 나눈 나머지로 하면 초당 2600개 정도,");
			System.out.println("4로 나눈 나머지로 하면 초당 3200개 정도,");
			System.out.println("5로 나눈 나머지로 하면 초당 4000개 정도...");
			System.out.println("6로 나눈 나머지로 하면 초당 4700개 정도...");
			System.out.println("7로 나눈 나머지로 하면 초당 5000개 정도...");
			System.out.println("초당7000개 정도는 다 들어감.");

			String keyinput2 = in.readLine();
			int divisionRatio=Integer.parseInt(keyinput2);
			int cnt1=0;
			int cnt2=2;
			int cnt0=10;

			//String tmpip="192.168.0.1";
			//String tmpHexIP=IPtoHexStr(tmpip);
			//String value="aabbccdd";
			//checkEntry(tmpip, tmpHexIP+value);
		//while (true) {
			System.out.println(getCurrentTimeMilli());
			int ran = (int)(Math.random()*255) ;
			String ranHex = Integer.toHexString(ran); 
		 	ranHex = ((ranHex.length()==1)?"0":"") + ranHex;	
			ranHex = ranHex + ranHex + ranHex + ranHex;
			System.out.println("rand="+ranHex);
			String currIP = "";
			System.out.println("start inserting DHT entry from 10.12"+subnetDigit+".0.2");
			for (int i = 0; i < 250000;i++){

					
				currIP = cnt0 + ".12"+subnetDigit+"." + cnt1 + "." + cnt2; 
				cnt2++;
				if(cnt2==256){
					cnt2 = 1;
					cnt1++;
				}
				if(cnt1==256){
					cnt1 = 1;
					cnt0++;
					System.out.print("65536 inserted ");
					System.out.println(getCurrentTimeMilli());

				}
				if(cnt0==256)
					break;
				
				String hostHexIP = IPtoHexStr(currIP);
				kserver.store(currIP, hostHexIP+ranHex);
				if ((i%divisionRatio)==0) 
					Thread.sleep(0,5000);

			}
			System.out.println("last ip : " + currIP);
			System.out.println("loop one is done");
			System.out.println(getCurrentTimeMilli());

			cnt0=10;
			cnt1=0;
			cnt2=2;
                        System.out.println("start inserting DHT entry from 10.14"+subnetDigit+".0.2");

			for (int i = 0; i < 250000;i++){
				currIP = cnt0 + ".14"+subnetDigit+"." + cnt1 + "." + cnt2; 
				cnt2++;
				if(cnt2==256){
					cnt2 = 1;
					cnt1++;
				}
				if(cnt1==256){
					cnt1 = 1;
					cnt0++;
					System.out.print("65536 inserted ");
					System.out.println(getCurrentTimeMilli());

				}
				if(cnt0==256)
					break;

				String hostHexIP = IPtoHexStr(currIP);
                                kserver.store(currIP, hostHexIP+ranHex);
				if ((i%divisionRatio)==0)
					Thread.sleep(0,5000);
			}
                        System.out.println("last ip : " + currIP);
			System.out.println("loop two is done");
			System.out.println(getCurrentTimeMilli());

			cnt0=10;
			cnt1=0;
			cnt2=2;
                        System.out.println("start inserting DHT entry from 10.16"+subnetDigit+".0.2");

			for (int i = 0; i < 250000;i++){
				currIP = cnt0 + ".16"+subnetDigit+"." + cnt1 + "." + cnt2; 
				cnt2++;
				if(cnt2==256){
					cnt2 = 1;
					cnt1++;
				}
				if(cnt1==256){
					cnt1 = 1;
					cnt0++;
					System.out.print("65536 inserted ");
					System.out.println(getCurrentTimeMilli());

				}
				if(cnt0==256)
					break;
				
				String hostHexIP = IPtoHexStr(currIP);
                                kserver.store(currIP, hostHexIP+ranHex);
				if ((i%divisionRatio)==0)
					Thread.sleep(0,5000);
			}
                        System.out.println("last ip : " + currIP);
			System.out.println("loop three is done");
			System.out.println(getCurrentTimeMilli());

			cnt0=10;
			cnt1=0;
			cnt2=2;
                        System.out.println("start inserting DHT entry from 10.18"+subnetDigit+".0.2");

			for (int i = 0; i < 250000;i++){
				currIP = cnt0 + ".18"+subnetDigit+"." + cnt1 + "." + cnt2; 
				cnt2++;
				if(cnt2==256){
					cnt2 = 1;
					cnt1++;
				}
				if(cnt1==256){
					cnt1 = 1;
					cnt0++;
					System.out.print("65536 inserted ");
					System.out.println(getCurrentTimeMilli());

				}
				if(cnt0==256)
					break;

                                String hostHexIP = IPtoHexStr(currIP);
                                kserver.store(currIP, hostHexIP+ranHex);
				if ((i%divisionRatio)==0)
					Thread.sleep(0,5000);
			}
                        System.out.println("last ip : " + currIP);
			System.out.println("loop four is done");
			System.out.println(getCurrentTimeMilli());

			System.out.println("every storing loop is done");
		}
		
	}

	public void store(String input, String value) throws IOException, NoSuchAlgorithmException {
		String tmp = sha1(input);
		
		peer.put(Number160.createHash(tmp)).setData(new Data(value)).start();
	}
	
	public static String IPtoHexStr (String a_input) {
		String input = a_input;
		String[] numArr = input.split("\\.");
		String output = "";
		for (int i = 0 ; i < 4 ; i ++){
			String hex = Integer.toHexString(Integer.parseInt(numArr[i]));
			hex = ((hex.length()==1)?"0":"") + hex;
			output = output+hex;
		}
		return output;
	} 
}
