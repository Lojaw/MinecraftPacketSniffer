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

    public static void main(String[] args) {
        List<String> packets = new ArrayList<>();
        Path filePath = Paths.get("C:", "Minecraft", "Traffic TTT Runde Modern.txt");

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

        boolean isFirstDurchlauf = true;

        for (String packet : packets) {
            String packetWithoutSpaces = packet.replace(" ", "");
            String redSequenceWithoutSpaces = reverseSequence(RED_SEQUENCE.replace(" ", ""));

            System.out.println(packetWithoutSpaces);

            if (isFirstDurchlauf) {
                System.out.println("Rote Sequenz: " + redSequenceWithoutSpaces);
                isFirstDurchlauf = false;
            }

            int packetRedCount = 0;

            for (int i = 0; i <= packetWithoutSpaces.length() - 6; i += 2) {
                String color = packetWithoutSpaces.substring(i, i + 6);

                //System.out.println(color);

                if (color.equals(redSequenceWithoutSpaces)) {
                    packetRedCount++;
                    System.out.println("Rot gefunden: " + color);
                }
            }

            redCount += packetRedCount;

            System.out.println("Packet Red Count: " + packetRedCount);
            System.out.println();
        }

        System.out.println("Red sequence found " + redCount + " times.");

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

}