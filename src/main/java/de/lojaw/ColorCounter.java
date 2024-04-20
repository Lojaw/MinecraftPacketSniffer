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
    private static final String RED_SEQUENCE = "85 00 84 00 83 00 82 00 80 00 01 00";
    private static final String BLUE_SEQUENCE = "52 00 00 00 00 00 00 c0 6d 74 64 83 17 5c ac 01";
    private static final String GREEN_SEQUENCE = "52 00 00 00 00 00 00 c0 6d 21 55 65 f1 fd 26 01";
    private static final String GRAY_SEQUENCE = "52 00 00 00 00 00 00 c0 6d 52 f1 20 9f e9 7c 01";

    public static void main(String[] args) {
        List<String> packets = new ArrayList<>();
        Path filePath = Paths.get("C:", "Minecraft", "WireShark_MC_Packets_3_Copy.txt");

        try (BufferedReader reader = new BufferedReader(new FileReader(String.valueOf(filePath)))) {
            String line;
            StringBuilder currentLine = new StringBuilder();
            StringBuilder packet = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s{3,}", 2);
                currentLine.append(parts[0]).append(" ");
                String prefix = getPrefix(line);
                String hexStringWithoutPrefix = currentLine.toString().trim().substring(prefix.length()).trim();
                System.out.println(hexStringWithoutPrefix);
                packet.append(hexStringWithoutPrefix).append(" ");
                currentLine.setLength(0);

                if (line.isEmpty() || line.trim().isEmpty()) {
                    String packetString = packet.toString().trim();
                    packets.add(packetString + ";");
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
        System.out.println(packetBuilder.toString());

        int redCount = 0;
        int blueCount = 0;
        int greenCount = 0;
        int grayCount = 0;

        for (String packet : packets) {
            String packetWithoutSpaces = packet.replace(" ", "");
            String redSequenceWithoutSpaces = RED_SEQUENCE.replace(" ", "");
            String blueSequenceWithoutSpaces = BLUE_SEQUENCE.replace(" ", "");
            String greenSequenceWithoutSpaces = GREEN_SEQUENCE.replace(" ", "");
            String graySequenceWithoutSpaces = GRAY_SEQUENCE.replace(" ", "");

            if (packetWithoutSpaces.contains(redSequenceWithoutSpaces)) {
                redCount++;
            }
            if (packetWithoutSpaces.contains(blueSequenceWithoutSpaces)) {
                blueCount++;
            }
            if (packetWithoutSpaces.contains(greenSequenceWithoutSpaces)) {
                greenCount++;
            }
            if (packetWithoutSpaces.contains(graySequenceWithoutSpaces)) {
                grayCount++;
            }
        }

        System.out.println("Red sequence found " + redCount + " times.");
        System.out.println("Blue sequence found " + blueCount + " times.");
        System.out.println("Green sequence found " + greenCount + " times.");
        System.out.println("Gray sequence found " + grayCount + " times.");

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
}