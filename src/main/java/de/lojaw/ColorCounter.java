package de.lojaw;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ColorCounter {

    private static final String RED_SEQUENCE = "ff 00 00";
    private static final String BA01_SEQUENCE = "ba 01";
    private static final String FILE_NAME1 = "3_Sequenz_WireShark_MC_Packets_3_Copy.txt";
    private static final String FILE_NAME2 = "Traffic TTT Runde Modern.txt";

    public static void main(String[] args) {
        List<String> packets = new ArrayList<>();
        Path filePath = Paths.get("C:", "Minecraft", FILE_NAME2);

        try (BufferedReader reader = new BufferedReader(new FileReader(String.valueOf(filePath)))) {
            String line;
            StringBuilder currentLine = new StringBuilder();
            StringBuilder packet = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s{3,}", 2);
                currentLine.append(parts[0]).append(" ");
                String prefix = getPrefix(line);
                String hexStringWithoutPrefix = currentLine.toString().trim().substring(prefix.length()).trim();
                //System.out.println(hexStringWithoutPrefix);
                packet.append(hexStringWithoutPrefix).append(" ");
                currentLine.setLength(0);

                if (line.isEmpty() || line.trim().isEmpty()) {
                    String packetString = packet.toString().trim();
                    //packets.add(packetString + ";");
                    packets.add(packetString);
                    packet.setLength(0);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Packets:");
        StringBuilder packetBuilder = new StringBuilder();
        for (String p : packets) {
            packetBuilder.append(p).append("\n");
        }
        System.out.println(packetBuilder);

        int redCount = 0;
        int ba01Count = 0;

        boolean isFirstDurchlauf = true;

        List<String> importpackets = new ArrayList<>();

        for (String packet : packets) {
            String packetWithoutSpaces = packet.replace(" ", "");
            String redSequenceWithoutSpaces = reverseSequence(RED_SEQUENCE.replace(" ", ""));

            boolean packetAdded = false;
            System.out.println(packetWithoutSpaces);

            if (isFirstDurchlauf) {
                System.out.println("Rote Sequenz: " + redSequenceWithoutSpaces);
                isFirstDurchlauf = false;
            }

            int packetRedCount = 0;


            for (int i = 0; i <= packetWithoutSpaces.length() - 6; i += 2) {
                String color = packetWithoutSpaces.substring(i, i + 6);

                //System.out.println(color);
                System.out.println("Red Sequence: " + color);

                if (color.equals(redSequenceWithoutSpaces)) {
                    packetRedCount++;
                    if (!packetAdded) {
                        importpackets.add(packetWithoutSpaces);
                        packetAdded = true;
                    }
                    System.out.println("Rot gefunden: " + color);
                }
            }
            redCount += packetRedCount;
            System.out.println("Packet Red Count: " + packetRedCount);

            int packetBa01Count = 0;
            for (int i = 0; i <= packetWithoutSpaces.length() - 4; i += 2) {
                String sequence = packetWithoutSpaces.substring(i, i + 4);
                System.out.println("Ba01 Sequence: " + sequence);
                if (sequence.equals("ac01") || sequence.equals("01ac") || sequence.equals("ba01") || sequence.equals("10ab") || sequence.equals(BA01_SEQUENCE.replace(" ", "")) || sequence.equals(reverseSequence(BA01_SEQUENCE.replace(" ", "")))) {
                    packetBa01Count++;
                    if (!packetAdded) {
                        importpackets.add(packetWithoutSpaces);
                        packetAdded = true;
                    }
                    System.out.println("ba01 gefunden: " + sequence);
                }
            }
            ba01Count += packetBa01Count;
            System.out.println("Packet ba01 Count: " + packetBa01Count);
            System.out.println();
        }

        System.out.println("Red sequence found " + redCount + " times.");
        System.out.println("ba01 sequence found " + ba01Count + " times.");



        List<String> entityIds = extractEntityIds("entity_ids Modern.txt");

        for (String packet : packets) {
            String packetWithoutSpaces = packet.replace(" ", "");

            // Suche nach den Entity-IDs
            for (String entityId : entityIds) {
                if (packetWithoutSpaces.contains(entityId)) {
                    System.out.println("Entity-ID " + entityId + " gefunden in Paket:");
                    System.out.println(packet);
                    System.out.println();
                }
            }

            // Restlicher Code für die Suche nach den Sequenzen...
        }

        // Ausgabe der importpackets-Liste
        System.out.println("Wichtige Pakete:");
        for (String importpacket : importpackets) {
            System.out.println(importpacket);
        }

    }

    private static String getPrefix(String line) {
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == ' ') {
                break;
            }
            prefix.append(c);
        }
        return prefix.toString();
    }

    private static String reverseSequence(String sequence) {
        StringBuilder reversed = new StringBuilder();
        for (int i = sequence.length() - 2; i >= 0; i -= 2) {
            reversed.append(sequence.substring(i, i + 2));
        }
        return reversed.toString();
    }

    private static List<String> extractEntityIds(String fileName) {
        List<String> entityIds = new ArrayList<>();
        Path filePath = Paths.get("C:", "Minecraft", fileName);

        try (BufferedReader reader = new BufferedReader(new FileReader(String.valueOf(filePath)))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("(ID: ")) {
                    int startIndex = line.indexOf("(ID: ") + 5;
                    int endIndex = line.indexOf(")", startIndex);
                    String entityId = line.substring(startIndex, endIndex);
                    entityIds.add(entityId);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return entityIds;
    }

}