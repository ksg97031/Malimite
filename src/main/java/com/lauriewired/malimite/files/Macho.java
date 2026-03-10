package com.lauriewired.malimite.files;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class Macho {
    private static final Logger LOGGER = Logger.getLogger(Macho.class.getName());

    // Mach-O Magic Numbers
    private static final int UNIVERSAL_MAGIC = 0xcafebabe;
    private static final int UNIVERSAL_CIGAM = 0xbebafeca;

    private List<Integer> cpuTypes;
    private List<Integer> cpuSubTypes;
    private List<Long> offsets;
    private List<Long> sizes;
    private boolean isUniversal;
    private String machoExecutablePath;
    private String outputDirectoryPath;
    private String machoExecutableName;
    private boolean isSwift = false;
    private boolean isEncrypted = false;
    private int cryptoff = 0;
    private int cryptsize = 0;

    // Mach-O single-arch magic numbers
    private static final int MH_MAGIC    = 0xFEEDFACE;
    private static final int MH_CIGAM    = 0xCEFAEDFE;
    private static final int MH_MAGIC_64 = 0xFEEDFACF;
    private static final int MH_CIGAM_64 = 0xCFFAEDFE;

    // Load command types for encryption info
    private static final int LC_ENCRYPTION_INFO    = 0x21;
    private static final int LC_ENCRYPTION_INFO_64 = 0x2C;

    public Macho(String machoExecutablePath, String outputDirectoryPath, String machoExecutableName) {
        this.isUniversal = false;
        this.cpuTypes = new ArrayList<>();
        this.cpuSubTypes = new ArrayList<>();
        this.offsets = new ArrayList<>();
        this.sizes = new ArrayList<>();
        this.machoExecutablePath = machoExecutablePath;
        this.outputDirectoryPath = outputDirectoryPath;
        this.machoExecutableName = machoExecutableName;

        processMacho();
    }

    public void processUniversalMacho(String selectedArchitecture) {
        extractMachoArchitecture(selectedArchitecture);

        // We do not care about the original macho anymore
        // This will effectively reset the instance variables for the extracted macho
        processMacho();
    }


    private void extractMachoArchitecture(String selectedArchitecture) {
        for (int i = 0; i < cpuTypes.size(); i++) {
            String arch = getArchitectureName(cpuTypes.get(i));
            String fullArchitecture = generateFullArchitectureString(arch, cpuTypes.get(i), cpuSubTypes.get(i));

            if (fullArchitecture.equals(selectedArchitecture)) {
                String tempFileName = machoExecutableName + "_extracted.macho";
                try {
                    extractSlice(machoExecutablePath, tempFileName, offsets.get(i), sizes.get(i));
                    LOGGER.info("Extracted " + arch + " slice to " + tempFileName);

                    replaceOldMachoWithNew(tempFileName);
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error extracting Mach-O slice", e);
                }
                break;
            }
        }
    }

    private void extractSlice(String inputFilePath, String outputFileName, long offset, long size) throws IOException {
        // Construct the full path for the output file
        String outputPath = outputDirectoryPath + File.separator + outputFileName;

        try (RandomAccessFile inputFile = new RandomAccessFile(inputFilePath, "r");
             FileOutputStream outputFile = new FileOutputStream(outputPath)) {

            inputFile.seek(offset);
            byte[] buffer = new byte[8192];
            long remaining = size;

            while (remaining > 0) {
                int bytesRead = inputFile.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (bytesRead == -1) break;

                outputFile.write(buffer, 0, bytesRead);
                remaining -= bytesRead;
            }
        }
    }

    private void replaceOldMachoWithNew(String tempFileName) throws IOException {
        File oldMacho = new File(machoExecutablePath);
        File extractedMacho = new File(outputDirectoryPath + File.separator + tempFileName);
        File newMacho = new File(machoExecutablePath);

        if (oldMacho.delete()) {
            if (!extractedMacho.renameTo(newMacho)) {
                throw new IOException("Failed to rename extracted Mach-O file.");
            }
            LOGGER.info("Replaced old Mach-O file with the extracted one.");
        } else {
            throw new IOException("Failed to delete old Mach-O file.");
        }
    }

    /*
     * Reads in a Mach-O file and sets instance variables based on type and architecture
     */
    private void processMacho() {
        File file = new File(this.machoExecutablePath);
        LOGGER.info("[MACHO] Processing: " + file.getAbsolutePath() + " (size=" + (file.length() / 1024 / 1024) + "MB)");

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            int magic = raf.readInt();
            LOGGER.info("[MACHO] Magic number: 0x" + Integer.toHexString(magic));
            if (magic == UNIVERSAL_MAGIC || magic == UNIVERSAL_CIGAM) {
                this.isUniversal = true;

                boolean reverseByteOrder = (magic == UNIVERSAL_CIGAM);
                int archCount = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                LOGGER.info("[MACHO] Universal binary with " + archCount + " architectures (reversed=" + reverseByteOrder + ")");
                for (int i = 0; i < archCount; i++) {
                    raf.seek(8L + i * 20L);
                    int cpuType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    int cpuSubType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    long offset = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    long size = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();

                    LOGGER.info("[MACHO] Arch[" + i + "]: " + getArchitectureName(cpuType) + " cpuType=0x" + Integer.toHexString(cpuType) + " subType=" + cpuSubType + " offset=" + offset + " size=" + (size / 1024 / 1024) + "MB");
                    cpuTypes.add(cpuType);
                    cpuSubTypes.add(cpuSubType);
                    offsets.add(offset);
                    sizes.add(size);
                }
            } else {
                this.isUniversal = false;
                LOGGER.info("[MACHO] Single architecture binary (magic=0x" + Integer.toHexString(magic) + ")");
            }

            // After processing the Mach-O headers, check for Swift and encryption
            detectSwift(file);
            detectEncryption(file);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "[MACHO] Error reading file: " + file.getAbsolutePath(), e);
        }
    }

    private void detectSwift(File file) {
        long fileSize = file.length();
        LOGGER.info("[DETECT-SWIFT] Starting Swift detection for: " + file.getName() + " (size: " + (fileSize / 1024 / 1024) + " MB)");
        try {
            // For large binaries, read in chunks to avoid OOM
            // Instead of loading entire file into memory as String
            byte[] searchPatterns = {
                // We'll search for patterns in chunks
            };

            boolean foundSwiftRuntime = false;
            boolean foundSwiftCore = false;
            boolean foundSwiftUnderscore = false;
            boolean foundSwiftMangling = false;

            int chunkSize = 8 * 1024 * 1024; // 8MB chunks
            byte[] buffer = new byte[chunkSize + 256]; // extra overlap for boundary matching
            int overlap = 256; // overlap to catch patterns split across chunks

            try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
                long position = 0;
                int carryOver = 0;

                while (position < fileSize) {
                    int readOffset = 0;
                    if (carryOver > 0) {
                        // Copy overlap from end of previous chunk
                        readOffset = carryOver;
                    }

                    raf.seek(position);
                    int bytesRead = raf.read(buffer, readOffset, chunkSize);
                    if (bytesRead <= 0) break;

                    int totalBytes = readOffset + bytesRead;
                    String chunk = new String(buffer, 0, totalBytes, StandardCharsets.UTF_8);

                    if (!foundSwiftRuntime && chunk.contains("Swift Runtime")) foundSwiftRuntime = true;
                    if (!foundSwiftCore && chunk.contains("SwiftCore")) foundSwiftCore = true;
                    if (!foundSwiftUnderscore && chunk.contains("_swift_")) foundSwiftUnderscore = true;
                    if (!foundSwiftMangling && chunk.contains("_$s")) foundSwiftMangling = true;

                    // Early exit if we found any indicator
                    if (foundSwiftRuntime || foundSwiftCore || foundSwiftUnderscore || foundSwiftMangling) {
                        LOGGER.info("[DETECT-SWIFT] Found Swift indicator early at position ~" + position);
                        break;
                    }

                    position += bytesRead;
                    // Keep overlap bytes for next iteration
                    if (bytesRead == chunkSize) {
                        System.arraycopy(buffer, totalBytes - overlap, buffer, 0, overlap);
                        carryOver = overlap;
                    }
                }
            }

            isSwift = foundSwiftRuntime || foundSwiftCore || foundSwiftUnderscore || foundSwiftMangling;
            LOGGER.info("[DETECT-SWIFT] Result: " + (isSwift ? "Swift" : "Objective-C") +
                " (Runtime=" + foundSwiftRuntime + ", Core=" + foundSwiftCore +
                ", _swift_=" + foundSwiftUnderscore + ", _$s=" + foundSwiftMangling + ")");
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "[DETECT-SWIFT] Error detecting Swift/Objective-C", e);
            isSwift = false;
        }
    }

    private void detectEncryption(File file) {
        LOGGER.info("[DETECT-ENCRYPT] Checking FairPlay DRM encryption for: " + file.getName());
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            int magic = raf.readInt();

            boolean is64bit;
            boolean littleEndian;

            if (magic == MH_MAGIC)         { is64bit = false; littleEndian = false; }
            else if (magic == MH_CIGAM)    { is64bit = false; littleEndian = true;  }
            else if (magic == MH_MAGIC_64) { is64bit = true;  littleEndian = false; }
            else if (magic == MH_CIGAM_64) { is64bit = true;  littleEndian = true;  }
            else {
                LOGGER.info("[DETECT-ENCRYPT] Not a single-arch Mach-O (magic=0x" + Integer.toHexString(magic) + "), skipping encryption check");
                return;
            }

            int headerSize = is64bit ? 32 : 28;

            // Read ncmds at offset 16
            raf.seek(16);
            int ncmds = readMachoInt(raf, littleEndian);

            // Skip to end of header where load commands begin
            raf.seek(headerSize);

            for (int i = 0; i < ncmds; i++) {
                long cmdOffset = raf.getFilePointer();
                int cmd = readMachoInt(raf, littleEndian);
                int cmdsize = readMachoInt(raf, littleEndian);

                if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
                    this.cryptoff = readMachoInt(raf, littleEndian);
                    this.cryptsize = readMachoInt(raf, littleEndian);
                    int cryptid = readMachoInt(raf, littleEndian);

                    this.isEncrypted = (cryptid != 0);
                    LOGGER.info("[DETECT-ENCRYPT] LC_ENCRYPTION_INFO found: cryptid=" + cryptid
                        + " cryptoff=0x" + Integer.toHexString(this.cryptoff)
                        + " cryptsize=" + (this.cryptsize / 1024 / 1024) + "MB");

                    if (this.isEncrypted) {
                        LOGGER.warning("[DETECT-ENCRYPT] *** BINARY IS FAIRPLAY DRM ENCRYPTED (cryptid=" + cryptid + ") ***");
                        LOGGER.warning("[DETECT-ENCRYPT] Decompilation will produce mostly halt_baddata() stubs.");
                        LOGGER.warning("[DETECT-ENCRYPT] Use a decrypted IPA for meaningful analysis.");
                    } else {
                        LOGGER.info("[DETECT-ENCRYPT] Binary is NOT encrypted (cryptid=0, previously decrypted)");
                    }
                    return;
                }

                // Advance to next load command
                if (cmdsize <= 0) {
                    LOGGER.warning("[DETECT-ENCRYPT] Invalid load command size at offset " + cmdOffset);
                    break;
                }
                raf.seek(cmdOffset + cmdsize);
            }

            LOGGER.info("[DETECT-ENCRYPT] No LC_ENCRYPTION_INFO found - binary is not encrypted");

        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "[DETECT-ENCRYPT] Error checking encryption", e);
        }
    }

    private static int readMachoInt(RandomAccessFile raf, boolean littleEndian) throws IOException {
        int value = raf.readInt();
        return littleEndian ? Integer.reverseBytes(value) : value;
    }

    public static class Architecture {
        private String name;
        private int cpuType;
        private int cpuSubType;
        
        public Architecture(String name, int cpuType, int cpuSubType) {
            this.name = name;
            this.cpuType = cpuType;
            this.cpuSubType = cpuSubType;
        }
        
        @Override
        public String toString() {
            return name + " (CPU Type: " + cpuType + ", SubType: " + cpuSubType + ")";
        }
        
        // Getters
        public String getName() { return name; }
        public int getCpuType() { return cpuType; }
        public int getCpuSubType() { return cpuSubType; }
    }

    private String getArchitectureName(int cpuType) {
        switch (cpuType) {
            case 0x00000007: return "Intel x86";
            case 0x01000007: return "Intel x86_64";
            case 0x0000000C: return "ARM";
            case 0x0100000C: return "ARM64";
            default: return "Unknown";
        }
    }

    public List<Architecture> getArchitectures() {
        List<Architecture> architectures = new ArrayList<>();
        for (int i = 0; i < cpuTypes.size(); i++) {
            architectures.add(new Architecture(
                getArchitectureName(cpuTypes.get(i)),
                cpuTypes.get(i),
                cpuSubTypes.get(i)
            ));
        }
        return architectures;
    }

    public List<String> getArchitectureStrings() {
        List<String> architectureStrings = new ArrayList<>();

        for (int i = 0; i < cpuTypes.size(); i++) {
            int cpuType = cpuTypes.get(i);
            int cpuSubType = cpuSubTypes.get(i);
            String arch = getArchitectureName(cpuType);

            String fullArchitecture = generateFullArchitectureString(arch, cpuType, cpuSubType);
            architectureStrings.add(fullArchitecture);
        }

        return architectureStrings;
    } 

    public void printArchitectures() {
        String arch = "";
        String fullArchitecture = "";

        for (int i = 0; i < cpuTypes.size(); i++) {
            int cpuType = cpuTypes.get(i);
            int cpuSubType = cpuSubTypes.get(i);
            arch = getArchitectureName(cpuType);

            fullArchitecture = generateFullArchitectureString(arch, cpuType, cpuSubType);
            LOGGER.info(fullArchitecture);
        }
    }

    private String generateFullArchitectureString(String arch, int cpuType, int cpuSubType) {
        return arch + " (CPU Type: " + cpuType + ", SubType: " + cpuSubType + ")";
    }

    public List<Integer> getCpuTypes() {
        return cpuTypes;
    }

    public List<Integer> getCpuSubTypes() {
        return cpuSubTypes;
    }

    public boolean isUniversalBinary() {
        return this.isUniversal;
    }

    public String getMachoExecutableName() {
        return this.machoExecutableName;
    }

    public boolean isSwift() {
        return isSwift;
    }

    public boolean isEncrypted() {
        return isEncrypted;
    }

    public int getCryptoff() {
        return cryptoff;
    }

    public int getCryptsize() {
        return cryptsize;
    }

    public String getEncryptionSummary() {
        if (!isEncrypted) return "Not encrypted";
        return String.format("FairPlay DRM encrypted (offset=0x%X, size=%dMB)",
            cryptoff, cryptsize / 1024 / 1024);
    }

    public long getSize() {
        File machoFile = new File(this.machoExecutablePath);
        return machoFile.length();
    }

    public Macho() {
        this.isUniversal = false;
        this.cpuTypes = new ArrayList<>();
        this.cpuSubTypes = new ArrayList<>();
        this.offsets = new ArrayList<>();
        this.sizes = new ArrayList<>();
        this.machoExecutablePath = "";
        this.outputDirectoryPath = "";
        this.machoExecutableName = "unknown";
        this.isSwift = false;
        this.isEncrypted = false;
    }

    public static Macho createEmpty() {
        return new Macho();
    }
}
