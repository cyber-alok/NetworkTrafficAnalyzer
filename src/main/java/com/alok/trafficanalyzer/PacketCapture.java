package com.alok.trafficanalyzer;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import java.util.List;
import java.util.Scanner;
public class PacketCapture {
	 public static void main(String[] args) {
		 try {
	            // Find all network devices
	            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
	            if (allDevs == null || allDevs.isEmpty()) {
	                System.out.println("No devices found!");
	                return;
	            }

	            // Print all devices
	            System.out.println("Available network devices:");
	            for (int i = 0; i < allDevs.size(); i++) {
	                System.out.println(i + ": " + allDevs.get(i).getName() + " (" + allDevs.get(i).getDescription() + ")");
	            }

	            // Ask user to select device
	            Scanner scanner = new Scanner(System.in);
	            System.out.print("Enter the device number to capture: ");
	            int deviceIndex = scanner.nextInt();
	            scanner.close();

	            if (deviceIndex < 0 || deviceIndex >= allDevs.size()) {
	                System.out.println("Invalid device index!");
	                return;
	            }

	            // Open selected device
	            PcapNetworkInterface device = allDevs.get(deviceIndex);
	            PcapHandle handle = device.openLive(
	                    65536, 
	                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 
	                    10000 // 10 seconds timeout
	            );

	            System.out.println("Starting capture on device: " + device.getName());

	            // Capture 10 packets
	            int packetCount = 0;
	            int maxPackets = 10;

	            while (packetCount < maxPackets) {
	                Packet packet = handle.getNextPacket();
	                if (packet != null) {
	                    System.out.println("Packet #" + (packetCount + 1) + ":");
	                    System.out.println(packet);
	                    packetCount++;
	                } else {
	                    System.out.println("No packet captured at this moment...");
	                }
	            }

	            handle.close();
	            System.out.println("Capture finished. Total packets captured: " + packetCount);

	        } catch (PcapNativeException e) {
	            System.out.println("Error opening device: " + e.getMessage());
	            e.printStackTrace();
	        } catch (NotOpenException e) {
	            System.out.println("Error capturing packet: " + e.getMessage());
	            e.printStackTrace();
	        } catch (Exception e) {
	            System.out.println("Exception: " + e.getMessage());
	            e.printStackTrace();
	        }
	    }

}
