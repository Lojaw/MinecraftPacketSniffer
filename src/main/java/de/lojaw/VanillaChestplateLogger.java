package de.lojaw;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class VanillaChestplateLogger {
    private static final String MINECRAFT_MODS_DIR = "C:\\Users\\jpsch\\AppData\\Roaming\\.minecraft\\mods";
    private static final String VANILLA_CHESTPLATE_LOG_FILE = "vanilla_leather_chestplate_log.txt";

    public static void main(String[] args) {
        try {
            // Ermittle das aktuelle Standardnetzwerkinterface
            PcapNetworkInterface defaultNif = PacketSniffer.getDefaultNetworkInterface();
            System.out.println("Default network interface: " + defaultNif.getName());

            // Lasse den Benutzer ein Interface auswählen
            PcapNetworkInterface nif = PacketSniffer.chooseNetworkInterface(defaultNif);
            if (nif == null) {
                return;
            }
            System.out.println("Selected network interface: " + nif.getName());

            // Starte das Paket-Sniffing
            startPacketCapture(nif);
        } catch (PcapNativeException e) {
            System.out.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void startPacketCapture(PcapNetworkInterface nif) {
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
                Path targetPath = Path.of(MINECRAFT_MODS_DIR, VANILLA_CHESTPLATE_LOG_FILE);
                Files.createDirectories(targetPath.getParent());

                startWritingToFile(capturedPackets, targetPath);

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

    private static void startWritingToFile(List<Packet> capturedPackets, Path targetPath) {
        Thread writeThread = new Thread(() -> {
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(targetPath.toFile(), true));
                 BufferedOutputStream leatherChestplateLog = new BufferedOutputStream(new FileOutputStream(Path.of(MINECRAFT_MODS_DIR, "leather_chestplate_log.txt").toFile(), true))) {
                while (!Thread.currentThread().isInterrupted()) {
                    if (!capturedPackets.isEmpty()) {
                        List<Packet> packetsCopy = new ArrayList<>(capturedPackets);
                        System.out.println("Writing " + packetsCopy.size() + " packets to file: " + targetPath);
                        for (Packet packet : packetsCopy) {
                            byte[] rawData = packet.getRawData();

                            // Erstelle einen ByteBuf aus den Rohdaten
                            ByteBuf buffer = Unpooled.wrappedBuffer(rawData);

                            // Rufe handlePacket auf, um das Paket zu verarbeiten
                            String leatherChestplateInfo = handlePacket(buffer);

                            // Schreibe die Lederbrustplatten-Informationen in die leather_chestplate_log.txt
                            if (leatherChestplateInfo != null) {
                                System.out.println("Leather Chestplate Info: " + leatherChestplateInfo);
                                leatherChestplateLog.write(leatherChestplateInfo.getBytes());
                                leatherChestplateLog.write(System.lineSeparator().getBytes());
                            }

                            // Nicht vergessen, den ByteBuf wieder freizugeben
                            buffer.release();
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

    private static String handlePacket(ByteBuf buffer) {
        int packetId = PacketSniffer.readVarInt(buffer);
        if (packetId == 60 || packetId == 1295132448) { // ClientboundSetEquipmentPacket
            int entityId = PacketSniffer.readVarInt(buffer);
            if (buffer.isReadable() && buffer.readableBytes() >= 1) {
                boolean hasData = buffer.readBoolean();
                StringBuilder packetString = new StringBuilder();
                while (buffer.isReadable()) {
                    if (buffer.readableBytes() >= 1) {
                        packetString.append("\nHEX DUMP: " + ByteBufUtil.hexDump(buffer) + "\n");
                        int slotData = buffer.readByte() & 0xFF;
                        if ((slotData & 0x80) != 0) {
                            //packetString.append("\nHEX DUMP: " + ByteBufUtil.hexDump(buffer) + "\n");
                            boolean hasItemData = (slotData & 0x40) != 0;
                            int slotId = slotData & 0x3F;
                            if (slotId == 6) { // Brustplatte
                                //packetString.append("\nHEX DUMP: " + ByteBufUtil.hexDump(buffer) + "\n");
                                if (hasItemData) {
                                    String itemName = PacketSniffer.readString(buffer);
                                    if (itemName.equals("minecraft:leather_chestplate")) {
                                        if (buffer.readableBytes() >= 1) {
                                            int count = buffer.readByte();
                                            int nbtDataLength = PacketSniffer.readVarInt(buffer);
                                            if (buffer.readableBytes() >= nbtDataLength) {
                                                String color = readColor(buffer, nbtDataLength);
                                                if (color.equals("#7F7F7F")) { // Graue Farbe
                                                    packetString.append("Gray Leather Chestplate received by Entity ").append(entityId);
                                                    packetString.append(" - ").append(PacketSniffer.getCurrentTimestamp());
                                                    packetString.append("\nHEX DUMP: " + ByteBufUtil.hexDump(buffer) + "\n");
                                                    return packetString.toString();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        //break;
                        return packetString.toString();
                    }
                }
            }
        }
        return null;
    }

    private static String readColor(ByteBuf buffer, int nbtDataLength) {
        int initialReaderIndex = buffer.readerIndex();
        while (buffer.readerIndex() - initialReaderIndex < nbtDataLength) {
            byte tagType = buffer.readByte();
            if (tagType == 10) { // Compound tag
                String tagName = PacketSniffer.readString(buffer);
                if (tagName.equals("tag")) {
                    int tagLength = PacketSniffer.readVarInt(buffer);
                    int tagInitialReaderIndex = buffer.readerIndex();
                    while (buffer.readerIndex() - tagInitialReaderIndex < tagLength) {
                        String subTagName = PacketSniffer.readString(buffer);
                        byte subTagType = buffer.readByte();
                        if (subTagName.equals("display")) {
                            int displayLength = PacketSniffer.readVarInt(buffer);
                            int displayInitialReaderIndex = buffer.readerIndex();
                            while (buffer.readerIndex() - displayInitialReaderIndex < displayLength) {
                                String displayTagName = PacketSniffer.readString(buffer);
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
                            skipTag(buffer, subTagType);
                        }
                    }
                } else {
                    skipTag(buffer, tagType);
                }
            } else if (tagType == 7) { // Byte array tag
                int byteArrayLength = PacketSniffer.readVarInt(buffer);
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
                int byteArrayLength = PacketSniffer.readVarInt(buffer);
                buffer.skipBytes(byteArrayLength);
                break;
            case 8: // String tag
                PacketSniffer.readString(buffer);
                break;
            case 9: // List tag
                int listType = buffer.readByte();
                int listLength = PacketSniffer.readVarInt(buffer);
                for (int i = 0; i < listLength; i++) {
                    skipTag(buffer, listType);
                }
                break;
            case 10: // Compound tag
                int compoundLength = PacketSniffer.readVarInt(buffer);
                buffer.skipBytes(compoundLength);
                break;
            case 11: // Int array tag
                int intArrayLength = PacketSniffer.readVarInt(buffer);
                buffer.skipBytes(intArrayLength * 4);
                break;
            case 12: // Long array tag
                int longArrayLength = PacketSniffer.readVarInt(buffer);
                buffer.skipBytes(longArrayLength * 8);
                break;
        }
    }
}