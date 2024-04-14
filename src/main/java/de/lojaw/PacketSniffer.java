package de.lojaw;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.CopyOnWriteArrayList;

public class PacketSniffer {
    private static final Logger logger = LogManager.getLogger(PacketSniffer.class);
    private static final String MINECRAFT_MODS_DIR = "C:\\Users\\jpsch\\AppData\\Roaming\\.minecraft\\mods";
    private static final String CAPTURE_FILE_NAME = "minecraft_packets.txt";

    public static void main(String[] args) {
        try {
            // Ermittle das aktuelle Standardnetzwerkinterface
            PcapNetworkInterface defaultNif = getDefaultNetworkInterface();
            System.out.println("Default network interface: " + defaultNif.getName());

            // Lasse den Benutzer ein Interface auswählen
            PcapNetworkInterface nif = chooseNetworkInterface(defaultNif);
            if (nif == null) {
                return;
            }
            System.out.println("Selected network interface: " + nif.getName());

            // Erstelle eine synchronisierte Liste, um die erfassten Pakete zu speichern
            List<Packet> capturedPackets = new CopyOnWriteArrayList<>();

            // Erstelle einen Packet Handler zum Verarbeiten der abgefangenen Pakete
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    capturedPackets.add(packet);
                }
            };

            // Öffne den Live-Capture für das Netzwerkinterface
            try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                // Setze einen Filter, um nur die gewünschten Pakete zu erfassen
                handle.setFilter("tcp port 25565", BpfProgram.BpfCompileMode.OPTIMIZE);

                System.out.println("Starting packet capture...");
                new Thread(() -> {
                    try {
                        handle.loop(-1, listener);
                    } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                        System.out.println("Error during packet capture: " + e.getMessage());
                        e.printStackTrace();
                    }
                }).start();

                // Speichere die erfassten Pakete in der Datei
                Path targetPath = Paths.get(MINECRAFT_MODS_DIR, CAPTURE_FILE_NAME);
                Files.createDirectories(targetPath.getParent());

                new Thread(() -> {
                    try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(targetPath.toFile(), true))) {
                        while (true) {
                            if (!capturedPackets.isEmpty()) {
                                List<Packet> packetsCopy = new ArrayList<>(capturedPackets);
                                System.out.println("Writing " + packetsCopy.size() + " packets to file: " + targetPath);

                                System.out.print("Choose the format to save the packets (1 - Hexadecimal, 2 - Binary, 3 - Raw): ");
                                Scanner scanner = new Scanner(System.in);
                                int formatChoice = scanner.nextInt();

                                for (Packet packet : packetsCopy) {
                                    byte[] rawData = packet.getRawData();

                                    if (formatChoice == 1) {
                                        // Hexadezimalformat
                                        StringBuilder hexBuilder = new StringBuilder();
                                        for (byte b : rawData) {
                                            hexBuilder.append(String.format("%02X ", b));
                                        }
                                        bos.write(hexBuilder.toString().getBytes());
                                        bos.write(System.lineSeparator().getBytes());
                                    } else if (formatChoice == 2) {
                                        // Binärformat
                                        StringBuilder binaryBuilder = new StringBuilder();
                                        for (byte b : rawData) {
                                            binaryBuilder.append(String.format("%8s ", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
                                        }
                                        bos.write(binaryBuilder.toString().getBytes());
                                        bos.write(System.lineSeparator().getBytes());
                                    } else if (formatChoice == 3) {
                                        // Rohdatenformat
                                        bos.write(rawData);
                                    }
                                }

                                bos.flush();
                                System.out.println("Packets written to file: " + targetPath);
                                capturedPackets.clear();
                            }
                            Thread.sleep(1000); // Pause für 1 Sekunde
                        }
                    } catch (IOException | InterruptedException e) {
                        System.out.println("Error writing packets to file: " + e.getMessage());
                        e.printStackTrace();
                    }
                }).start();

                // Warte auf Benutzerinteraktion, um das Programm zu beenden
                System.out.println("Press Enter to stop...");
                System.in.read();
            }
        } catch (PcapNativeException | IOException | NotOpenException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static PcapNetworkInterface getDefaultNetworkInterface() {
        try {
            // Rufe PowerShell-Befehl auf, um aktuelle Netzwerkadapter zu ermitteln
            Process process = Runtime.getRuntime().exec("powershell.exe Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs.isEmpty()) {
                logger.error("No network interfaces found.");
                return null;
            }

            List<String> interfaceNames = new ArrayList<>();
            List<String> interfaceDescriptions = new ArrayList<>();
            List<String> interfaceMacAddresses = new ArrayList<>();

            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    String[] parts = line.split("\\s+", 3);
                    if (parts.length == 3) {
                        interfaceNames.add(parts[0]);
                        interfaceDescriptions.add(parts[1]);
                        interfaceMacAddresses.add(parts[2]);
                    }
                }
            }

            // Finde den Index des Standardinterfaces in der allDevs-Liste
            for (int i = 0; i < allDevs.size(); i++) {
                String interfaceName = allDevs.get(i).getName();
                if (interfaceNames.contains(interfaceName)) {
                    int index = interfaceNames.indexOf(interfaceName);
                    return allDevs.get(i);
                }
            }

            // Verwende als Fallback das erste Interface in der Liste
            return allDevs.get(0);
        } catch (IOException | PcapNativeException e) {
            logger.error("Error getting default network interface: {}", e.getMessage());
            return null;
        }
    }

    private static PcapNetworkInterface chooseNetworkInterface(PcapNetworkInterface defaultNif) throws PcapNativeException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs.isEmpty()) {
            logger.error("No network interfaces found.");
            return null;
        }

        System.out.println("Available network interfaces:");
        System.out.println("0. " + defaultNif.getName() + " (" + defaultNif.getDescription() + ")");

        for (int i = 0; i < allDevs.size(); i++) {
            if (!allDevs.get(i).getName().equals(defaultNif.getName())) {
                System.out.println((i + 1) + ". " + allDevs.get(i).getName() + " (" + allDevs.get(i).getDescription() + ")");
            }
        }

        System.out.print("Enter the number of the interface to use (or 0 for the default): ");
        Scanner scanner = new Scanner(System.in);
        int choice = scanner.nextInt();
        scanner.close();

        if (choice == 0) {
            return defaultNif;
        } else if (choice > 0 && choice <= allDevs.size()) {
            return allDevs.get(choice - 1);
        } else {
            logger.error("Invalid choice. Using default interface.");
            return defaultNif;
        }
    }
}