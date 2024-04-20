package de.lojaw;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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
            PacketListener listener = capturedPackets::add;

            // Öffne den Live-Capture für das Netzwerkinterface
            try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                // Setze einen Filter, um nur die gewünschten Pakete zu erfassen
                handle.setFilter("tcp port 20300", BpfProgram.BpfCompileMode.OPTIMIZE);

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
        }
    }

    private static void startWritingToFile(List<Packet> capturedPackets, Path targetPath, int formatChoice) {
        Thread writeThread = new Thread(() -> {
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(targetPath.toFile(), true));
                 BufferedOutputStream leatherChestplateLog = new BufferedOutputStream(new FileOutputStream(Path.of(MINECRAFT_MODS_DIR, "leather_chestplate_log.txt").toFile(), true))) {
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

                                    // Rufe handlePacket auf, um das Paket zu verarbeiten
                                    String leatherChestplateInfo = handlePacket(buffer);

                                    // Schreibe die Hexadezimaldarstellung in die minecraft_packets.txt
                                    bos.write(hexString.getBytes());
                                    bos.write(System.lineSeparator().getBytes());

                                    // Schreibe die Lederbrustplatten-Informationen in die leather_chestplate_log.txt
                                    if (leatherChestplateInfo != null) {
                                        leatherChestplateLog.write(leatherChestplateInfo.getBytes());
                                        leatherChestplateLog.write(System.lineSeparator().getBytes());
                                    }

                                    // Nicht vergessen, den ByteBuf wieder freizugeben
                                    buffer.release();
                                } else {
                                    bos.write(hexString.getBytes());
                                    bos.write(System.lineSeparator().getBytes());
                                }
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
                        leatherChestplateLog.flush();
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

    public static String handlePacket(ByteBuf buffer) {
        int packetId = readVarInt(buffer);
        System.out.println("Packet ID: " + packetId);
        System.out.println("Remaining readable bytes: " + buffer.readableBytes());

        //if (isCustomProtocollibPacket(buffer)) {
            //return handleCustomProtocollibPacket(buffer);
        //}

        //if (packetId == 60 || packetId == 1295132448) { // ClientboundSetEquipmentPacket
            int entityId = readVarInt(buffer);
            //System.out.println("Remaining readable bytes after reading entity ID: " + buffer.readableBytes());
            //System.out.println("Entity ID: " + entityId);

            if (buffer.isReadable() && buffer.readableBytes() >= 1) {
                boolean hasData = buffer.readBoolean();

                StringBuilder packetString = new StringBuilder();
                //packetString.append("Entity ").append(entityId).append("  ;  ");
                //packetString.append("HEXDUMP: " + ByteBufUtil.hexDump(buffer));
                boolean hasLeatherChestplate = false;
                String leatherChestplateInfo = null;

                while (buffer.isReadable()) {
                    packetString.append("HEX DUMP: ").append(ByteBufUtil.hexDump(buffer));
                    if (buffer.readableBytes() >= 1) {
                        int slotData = buffer.readByte() & 0xFF;
                        //packetString.append(String.format("%02X ", slotData));

                        if ((slotData & 0x80) != 0) {
                            boolean hasItemData = (slotData & 0x40) != 0;
                            int slotId = slotData & 0x3F;
                            System.out.println("SLOT ID: " + slotId);

                            if (slotId == 38) { // Brustplatte
                                if (hasItemData) {
                                    System.out.println("Before readString: " + ByteBufUtil.hexDump(buffer));
                                    String itemName = readString(buffer);
                                    System.out.println("After readString: " + ByteBufUtil.hexDump(buffer));
                                    System.out.println("Item name: " + itemName);

                                    if (itemName.contains("chestplate")) {
                                        if (buffer.readableBytes() >= 1) {
                                            int count = buffer.readByte();
                                            int nbtDataLength = readVarInt(buffer);
                                            if (buffer.readableBytes() >= nbtDataLength) {
                                                String color = readColor(buffer, nbtDataLength);

                                                //packetString.append(itemName).append(", Count ").append(count).append(", Color ").append(color);
                                                //packetString.append(" - ").append(getCurrentTimestamp());

                                                hasLeatherChestplate = true;
                                                leatherChestplateInfo = packetString.toString();

                                                String leatherChestplateColor = extractLeatherChestplateColor(packetString.toString());
                                                if (leatherChestplateColor != null) {
                                                    //packetString.append(" ").append(leatherChestplateColor);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    //packetString.append("Brustplatte ausgezogen - ").append(getCurrentTimestamp());
                                    //hasLeatherChestplate = true;
                                    //leatherChestplateInfo = packetString.toString();
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
                return packetString.toString();
                //if (hasLeatherChestplate) {
                    //return leatherChestplateInfo;
                //}
            }
        //}

        // ...

        return null;
    }

    public static String extractLeatherChestplateColor(String packetData) {
        String[] parts = packetData.split(" ");
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].equals("A6")) {
                if (i >= 2) {
                    String colorHex = parts[i - 2];
                    int colorInt = Integer.parseInt(colorHex, 16);
                    java.awt.Color color = new java.awt.Color(colorInt);
                    return String.format("Leather Chestplate Color: RGB(%d, %d, %d)", color.getRed(), color.getGreen(), color.getBlue());
                }
            }
        }
        return null;
    }

    public static String handleSetSlotPacket(ByteBuf buffer) {
        // Implementiere die Logik zum Parsen des Set Slot Pakets
        // Ähnlich wie in handlePacket, aber spezifisch für den Inhalt des Set Slot Pakets
        // Verwende readSlotData, um die Slot-Daten auszulesen
        return null;
    }

    public static String handleEntityMetadataPacket(ByteBuf buffer) {
        // Implementiere die Logik zum Parsen des Entity Metadata Pakets
        // Ähnlich wie in handlePacket, aber spezifisch für den Inhalt des Entity Metadata Pakets
        // Durchlaufe die Metadaten und suche nach Einträgen, die sich auf die Rüstung beziehen
        return null;
    }

    public static String handleCustomPacket(ByteBuf buffer, String channel) {
        StringBuilder packetString = new StringBuilder();
        packetString.append("Custom Plugin Packet received on channel ").append(channel).append("\n");

        // Beispielcode zum Auslesen eines Strings und einer Farbe aus dem Paket
        String customString = readString(buffer);
        String customColor = readColor(buffer, buffer.readableBytes());

        packetString.append("Custom String: ").append(customString).append("\n");
        packetString.append("Custom Color: ").append(customColor).append("\n");

        // Hier weiteren Code zum Parsen der custom Paketdaten einfügen

        packetString.append("\n");
        return packetString.toString();
    }

    public static String getCurrentTimestamp() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return LocalDateTime.now().format(formatter);
    }

    public static String readString(ByteBuf buffer) {
        if (buffer.readableBytes() >= 2) {
            int length = buffer.readShort();
            if (length >= 0 && buffer.readableBytes() >= length) {
                byte[] bytes = new byte[length];
                buffer.readBytes(bytes);
                return new String(bytes, StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    private static String readColor(ByteBuf buffer, int nbtDataLength) {
        int initialReaderIndex = buffer.readerIndex();
        while (buffer.readerIndex() - initialReaderIndex < nbtDataLength) {
            byte tagType = buffer.readByte();
            if (tagType == 10) { // Compound tag
                String tagName = readString(buffer);
                if (tagName.equals("display")) {
                    int displayLength = readVarInt(buffer);
                    int displayInitialReaderIndex = buffer.readerIndex();
                    while (buffer.readerIndex() - displayInitialReaderIndex < displayLength) {
                        String displayTagName = readString(buffer);
                        byte displayTagType = buffer.readByte();
                        if (displayTagName.equals("color")) {
                            if (displayTagType == 3) { // Int tag
                                int colorValue = buffer.readInt();
                                return String.format("#%06X", colorValue);
                            } else {
                                skipTag(buffer, displayTagType);
                            }
                        } else {
                            skipTag(buffer, displayTagType);
                        }
                    }
                } else {
                    skipTag(buffer, tagType);
                }
            } else if (tagType == 7) { // Byte array tag
                int byteArrayLength = readVarInt(buffer);
                if (byteArrayLength == 2) {
                    byte colorByte1 = buffer.readByte();
                    byte colorByte2 = buffer.readByte();
                    int colorValue = (colorByte1 << 8) | (colorByte2 & 0xFF);
                    return String.format("#%06X", colorValue);
                } else {
                    buffer.skipBytes(byteArrayLength);
                }
            } else {
                skipTag(buffer, tagType);
            }
        }
        return "Unknown";
    }

    public static String handleCustomProtocollibPacket(ByteBuf buffer) {
        StringBuilder packetString = new StringBuilder();
        packetString.append("Custom Protocollib Packet received\n");

        // Lese die relevanten Daten aus dem custom Protocollib-Packet
        String packetData = ByteBufUtil.hexDump(buffer);

        if (packetData.contains("A0 4D A6")) {
            packetString.append("Leather Chestplate Color: RGB(164, 0, 77)\n");
        }

        return packetString.toString();
    }

    private static boolean isCustomProtocollibPacket(ByteBuf buffer) {
        // Überprüfe, ob das Paket das custom Protocollib-Packet ist
        String packetData = ByteBufUtil.hexDump(buffer);
        return packetData.contains("A0 4D A6");
    }

    private static void skipTag(ByteBuf buffer, int tagType) {
        switch (tagType) {
            case 0: // End tag
                break;
            case 1: // Byte tag
                buffer.skipBytes(1);
                break;
            case 2: // Short tag
                buffer.skipBytes(2);
                break;
            case 3: // Int tag
                buffer.skipBytes(4);
                break;
            case 4: // Long tag
                buffer.skipBytes(8);
                break;
            case 5: // Float tag
                buffer.skipBytes(4);
                break;
            case 6: // Double tag
                buffer.skipBytes(8);
                break;
            case 7: // Byte array tag
                int byteArrayLength = readVarInt(buffer);
                buffer.skipBytes(byteArrayLength);
                break;
            case 8: // String tag
                readString(buffer);
                break;
            case 9: // List tag
                int listType = buffer.readByte();
                int listLength = readVarInt(buffer);
                for (int i = 0; i < listLength; i++) {
                    skipTag(buffer, listType);
                }
                break;
            case 10: // Compound tag
                int compoundLength = readVarInt(buffer);
                buffer.skipBytes(compoundLength);
                break;
            case 11: // Int array tag
                int intArrayLength = readVarInt(buffer);
                buffer.skipBytes(intArrayLength * 4);
                break;
            case 12: // Long array tag
                int longArrayLength = readVarInt(buffer);
                buffer.skipBytes(longArrayLength * 8);
                break;
        }
    }

    public static int readVarInt(ByteBuf buffer) {
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

    public static PcapNetworkInterface getDefaultNetworkInterface() {
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

    public static PcapNetworkInterface chooseNetworkInterface(PcapNetworkInterface defaultNif) throws PcapNativeException {
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