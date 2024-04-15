package de.lojaw;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
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
    private static final String[] PACKET_FORMATS = {"Hexadecimal", "Binary", "Raw"};

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

            // Wähle das Paketformat aus
            int packetFormat = 1; // 1 = Hexadecimal, 2 = Binary, 3 = Raw
            System.out.println("Using " + PACKET_FORMATS[packetFormat - 1] + " format.");

            // Starte das Paket-Sniffing
            startPacketCapture(nif, packetFormat);
        } catch (PcapNativeException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static int choosePacketFormat(String[] formatOptions) {
        System.out.println("Available packet formats:");
        for (int i = 0; i < formatOptions.length; i++) {
            System.out.println((i + 1) + ". " + formatOptions[i]);
        }

        Scanner scanner = new Scanner(System.in);
        int choice;
        while (true) {
            System.out.print("Enter the number of the format to use: ");
            if (scanner.hasNextInt()) {
                choice = scanner.nextInt();
                scanner.nextLine(); // Consume the newline character
                if (choice >= 1 && choice <= formatOptions.length) {
                    System.out.println("Selected format: " + formatOptions[choice - 1]);
                    return choice;
                } else {
                    System.out.println("Invalid choice. Please enter a valid number.");
                }
            } else {
                System.out.println("Invalid input. Please enter a valid number.");
                scanner.nextLine(); // Consume the invalid input
            }
        }
    }

    private static void startPacketCapture(PcapNetworkInterface nif, int formatChoice) {
        Thread writeThread = null;
        try {
            // Erstelle eine synchronisierte Liste, um die erfassten Pakete zu speichern
            List<Packet> capturedPackets = new CopyOnWriteArrayList<>();

            // Erstelle einen Packet Handler zum Verarbeiten der abgefangenen Pakete
            PacketListener listener = packet -> capturedPackets.add(packet);

            // Öffne den Live-Capture für das Netzwerkinterface
            try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                // Setze einen Filter, um nur die gewünschten Pakete zu erfassen
                handle.setFilter("tcp port 25565", BpfProgram.BpfCompileMode.OPTIMIZE);

                // Speichere die erfassten Pakete in der Datei
                Path targetPath = Path.of(MINECRAFT_MODS_DIR, CAPTURE_FILE_NAME);
                Files.createDirectories(targetPath.getParent());

                startWritingToFile(capturedPackets, targetPath, formatChoice);

                // Starte die Paketerfassung
                System.out.println("Starting packet capture...");
                System.out.println("Press Enter to stop capturing packets...");
                handle.loop(-1, listener);

                // Starte einen separaten Thread, um auf die Benutzereingabe zu warten
                Thread stopThread = new Thread(() -> {
                    System.out.println("Press Enter to stop capturing packets...");
                    try {
                        System.in.read();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    // Beende die Paketerfassung
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException e) {
                        e.printStackTrace();
                    }
                });
                stopThread.start();

                // Starte die Paketerfassung
                System.out.println("Starting packet capture...");
                handle.loop(-1, listener);

                // Warte, bis der stopThread beendet ist
                stopThread.join();


            }

        } catch (PcapNativeException | IOException | NotOpenException | InterruptedException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Unterbreche den Schreibthread und warte darauf, dass er beendet wird
            if (writeThread != null) {
                writeThread.interrupt();
                try {
                    writeThread.join();
                } catch (InterruptedException e) {
                    System.out.println("Error interrupting write thread: " + e.getMessage());
                }
            }
        }
    }

    private static void startWritingToFile(List<Packet> capturedPackets, Path targetPath, int formatChoice) {
        Thread writeThread = new Thread(() -> {
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(targetPath.toFile(), true))) {
                while (!Thread.currentThread().isInterrupted()) {
                    if (!capturedPackets.isEmpty()) {
                        List<Packet> packetsCopy = new ArrayList<>(capturedPackets);
                        System.out.println("Writing " + packetsCopy.size() + " packets to file: " + targetPath);
                        for (Packet packet : packetsCopy) {
                            byte[] rawData = packet.getRawData();

                            if (formatChoice == 1) {
                                // Hexadezimalformat
                                StringBuilder hexBuilder = new StringBuilder();
                                for (byte b : rawData) {
                                    hexBuilder.append(String.format("%02X ", b));
                                }
                                String hexString = hexBuilder.toString().trim();

                                // Überprüfe, ob das ClientboundSetEquipmentPacket vorliegt
                                if (hexString.contains("59")) {
                                    System.out.println("ClientboundSetEquipmentPacket detected!");

                                    // Erstelle einen ByteBuf aus den Rohdaten
                                    ByteBuf buffer = Unpooled.wrappedBuffer(rawData);
                                    System.out.println("ByteBuf content:");
                                    printHexDump(buffer);

                                    // Rufe handlePacket auf, um das Paket zu verarbeiten
                                    handlePacket(buffer);

                                    // Nicht vergessen, den ByteBuf wieder freizugeben
                                    buffer.release();
                                }

                                bos.write(hexString.getBytes());
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
        });
        writeThread.start();
    }

    public static void handlePacket(ByteBuf buffer) {
        int packetId = readVarInt(buffer);
        System.out.println("Packet ID: " + packetId);
        System.out.println("Remaining readable bytes: " + buffer.readableBytes());
        if (packetId == 60 || packetId == 1295132448) { // ClientboundSetEquipmentPacket
            int entityId = readVarInt(buffer);
            System.out.println("Remaining readable bytes after reading entity ID: " + buffer.readableBytes());
            System.out.println("Entity ID: " + entityId);

            if (buffer.isReadable() && buffer.readableBytes() >= 1) {
                boolean hasData = buffer.readBoolean();
                while (hasData && buffer.isReadable()) {
                    if (buffer.readableBytes() >= 1) {
                        int slot = buffer.readByte() & 0xFF; // Umwandlung in unsigned Byte
                        boolean hasItemData = buffer.readableBytes() >= 1 && buffer.readBoolean();
                        if (slot == 6) {
                            if (buffer.readableBytes() >= 1) {
                                int slotData = buffer.readByte() & 0xFF; // Umwandlung in unsigned Byte
                                if (slotData == 0x80) { // Brustplatte
                                    if (hasItemData) {
                                        int itemId = readVarInt(buffer);
                                        if (buffer.readableBytes() >= 1) {
                                            int count = buffer.readByte();
                                            int nbtDataLength = readVarInt(buffer);
                                            if (buffer.readableBytes() >= nbtDataLength) {
                                                buffer.skipBytes(nbtDataLength);
                                                System.out.println("Brustplatte angelegt für Entity " + entityId + ": Item-ID " + itemId + ", Count " + count);
                                            } else {
                                                // Nicht genügend Bytes im ByteBuf, um die NBT-Daten zu überspringen
                                                break;
                                            }
                                        } else {
                                            // Nicht genügend Bytes im ByteBuf, um den Count-Wert zu lesen
                                            break;
                                        }
                                    } else {
                                        System.out.println("Brustplatte ausgezogen für Entity " + entityId);
                                    }
                                } else {
                                    // Zurücksetzen des Lesezeigers
                                    buffer.readerIndex(buffer.readerIndex() - 1);
                                    skipSlotData(buffer);
                                }
                            } else {
                                // Nicht genügend Bytes im ByteBuf, um slotData zu lesen
                                break;
                            }
                        } else {
                            skipSlotData(buffer);
                        }
                    } else {
                        // Nicht genügend Bytes im ByteBuf, um den Slot-Wert zu lesen
                        break;
                    }
                    hasData = buffer.isReadable() && buffer.readableBytes() >= 1 && buffer.readBoolean();
                }
            }
        }
    }

    private static void printHexDump(ByteBuf buffer) {
        int rowSize = 16;
        StringBuilder hexDump = new StringBuilder();
        for (int i = 0; i < buffer.readableBytes(); i += rowSize) {
            hexDump.append(String.format("%04X: ", i));
            int end = Math.min(i + rowSize, buffer.readableBytes());
            for (int j = i; j < end; j++) {
                hexDump.append(String.format("%02X ", buffer.getByte(j)));
            }
            for (int j = end; j < i + rowSize; j++) {
                hexDump.append("   ");
            }
            hexDump.append(" ");
            for (int j = i; j < end; j++) {
                byte b = buffer.getByte(j);
                hexDump.append(b >= 32 && b <= 126 ? (char) b : '.');
            }
            hexDump.append("\n");
        }
        System.out.println(hexDump.toString());
    }

    private static int readVarInt(ByteBuf buffer) {
        // Implementierung zum Lesen eines VarInt
        // Dies ist eine vereinfachte Version, die nur positive Zahlen unterstützt
        int value = 0;
        int shift = 0;
        byte currentByte;
        do {
            if (buffer.isReadable()) {
                currentByte = buffer.readByte();
                value |= (currentByte & 0x7F) << shift;
                shift += 7;
            } else {
                // Nicht genügend Bytes im ByteBuf, um den VarInt-Wert zu lesen
                // Hier können Sie einen Fehlerhandling-Code einfügen oder einen Standardwert zurückgeben
                return 0; // Standardwert 0 zurückgeben
            }
        } while ((currentByte & 0x80) != 0);
        return value;
    }

    private static void skipSlotData(ByteBuf buffer) {
        if (buffer.isReadable() && buffer.readableBytes() >= 1) {
            boolean hasItemData = buffer.readBoolean();
            if (hasItemData) {
                readVarInt(buffer); // Item ID
                if (buffer.isReadable() && buffer.readableBytes() >= 1) {
                    buffer.readByte(); // Count
                    int nbtDataLength = readVarInt(buffer);
                    if (nbtDataLength >= 0) {
                        if (buffer.readableBytes() >= nbtDataLength) {
                            buffer.skipBytes(nbtDataLength); // NBT Data
                        } else {
                            // Nicht genügend Bytes im ByteBuf, um die NBT-Daten zu überspringen
                            // Hier können Sie einen Fehlerhandling-Code einfügen
                        }
                    } else {
                        // Ungültiger negativer Wert für nbtDataLength
                        // Hier können Sie einen Fehlerhandling-Code einfügen oder das Paket überspringen
                    }
                } else {
                    // Nicht genügend Bytes im ByteBuf, um den Count-Wert zu lesen
                    // Hier können Sie einen Fehlerhandling-Code einfügen
                }
            }
        } else {
            // Nicht genügend Bytes im ByteBuf, um den hasItemData-Wert zu lesen
            // Hier können Sie einen Fehlerhandling-Code einfügen
        }
    }

    private static void readNbt(ByteBuf buffer) {
        int nbtDataLength = readVarInt(buffer);
        buffer.skipBytes(nbtDataLength);
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