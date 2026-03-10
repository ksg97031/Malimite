package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.configuration.LibraryDefinitions;
import com.lauriewired.malimite.database.SQLiteDBHandler;

import java.nio.file.Paths;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.logging.Logger;
import java.util.logging.Level;

import java.util.function.Consumer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

public class GhidraProject {
    private static final Logger LOGGER = Logger.getLogger(GhidraProject.class.getName());
    private String ghidraProjectName;
    private Config config;
    private String scriptPath;
    private SQLiteDBHandler dbHandler;
    private static final int BASE_PORT = 8765;
    private static final int MAX_PORT_ATTEMPTS = 10;
    private Consumer<String> consoleOutputCallback;

    public GhidraProject(String infoPlistBundleExecutable, String executableFilePath, Config config, SQLiteDBHandler dbHandler, Consumer<String> consoleOutputCallback) {
        this.ghidraProjectName = infoPlistBundleExecutable + "_malimite";
        this.config = config;
        this.dbHandler = dbHandler;
        this.consoleOutputCallback = consoleOutputCallback;
        // Set script path based on current directory and OS
        String currentDir = System.getProperty("user.dir");
        this.scriptPath = Paths.get(currentDir, "DecompilerBridge", "ghidra").toString();

        LOGGER.info("Initializing GhidraProject with executable: " + infoPlistBundleExecutable);
        LOGGER.info("Script path: " + scriptPath);
    }

    public void decompileMacho(String executableFilePath, String projectDirectoryPath, Macho targetMacho, boolean dynamicFile) {
        LOGGER.info("Starting Ghidra decompilation for: " + executableFilePath);
        
        // Try ports until we find an available one
        ServerSocket serverSocket = null;
        int port = BASE_PORT;
        int attempts = 0;
        
        while (attempts < MAX_PORT_ATTEMPTS && serverSocket == null) {
            try {
                serverSocket = new ServerSocket(port);
                LOGGER.info("Successfully bound to port " + port);
            } catch (IOException e) {
                LOGGER.warning("Port " + port + " is in use, trying next port");
                port++;
                attempts++;
                if (attempts >= MAX_PORT_ATTEMPTS) {
                    throw new RuntimeException("Unable to find available port after " + MAX_PORT_ATTEMPTS + " attempts");
                }
            }
        }

        try (ServerSocket finalServerSocket = serverSocket) {  // Ensure socket gets closed
            String analyzeHeadless = getAnalyzeHeadlessPath();
            
            // Get active libraries and join them with commas
            List<String> activeLibraries = LibraryDefinitions.getActiveLibraries(config);
            String librariesArg = String.join(",", activeLibraries);

            ProcessBuilder builder = new ProcessBuilder(    
                analyzeHeadless,
                projectDirectoryPath,
                this.ghidraProjectName,
                "-import",
                executableFilePath,
                "-scriptPath",
                scriptPath,
                "-postScript",
                "DumpClassData.java",
                String.valueOf(port),  // Use the port we found
                librariesArg,
                "-enableAnalyzer", "Objective-C",
                "-enableAnalyzer", "String Extraction",
                "-disableAnalyzer", "Decompiler Parameter ID",
                "-disableAnalyzer", "DWARF",
                "-skipAnalysisPrompt",
                "-deleteProject"
            );
            
            // Redirect Ghidra's output and error streams
            builder.redirectErrorStream(true);
            Process process = builder.start();

            // Read Ghidra's output in a separate thread
            Thread outputThread = new Thread(() -> {
                try (BufferedReader ghidraOutput = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = ghidraOutput.readLine()) != null) {
                        final String outputLine = line;
                        if (consoleOutputCallback != null) {
                            consoleOutputCallback.accept("Ghidra: " + outputLine);
                        }
                        System.out.println("Ghidra Output: " + line);
                    }
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error reading Ghidra output", e);
                }
            });
            outputThread.start();

            LOGGER.info("Starting Ghidra headless analyzer with command: " + String.join(" ", builder.command()));
            LOGGER.info("Waiting for Ghidra script connection on port " + port);
            
            Socket socket = serverSocket.accept();
            socket.setSoTimeout(60000); // 1 minute timeout for heartbeat
            LOGGER.info("Connection established with Ghidra script");

            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                // Wait for heartbeat
                String heartbeat = in.readLine();
                if (!"HEARTBEAT".equals(heartbeat)) {
                    throw new RuntimeException("Did not receive heartbeat from Ghidra script");
                }
                LOGGER.info("Received heartbeat from Ghidra script");
                
                // Close the initial heartbeat connection
                socket.close();

                // Accept the new connection for actual data transfer
                // Set 10-minute timeout to detect Ghidra crashes during analysis
                finalServerSocket.setSoTimeout(600000);
                LOGGER.info("[SOCKET] Waiting for Ghidra data connection (timeout=10min)...");
                try {
                    socket = finalServerSocket.accept();
                } catch (java.net.SocketTimeoutException ste) {
                    LOGGER.severe("[SOCKET] Timed out waiting for Ghidra data connection after 10 minutes - Ghidra may have crashed");
                    throw new RuntimeException("Ghidra script did not connect for data transfer within 10 minutes. Check Ghidra logs above.", ste);
                }
                socket.setSoTimeout(0); // No timeout for data transfer
                LOGGER.info("[SOCKET] Ghidra data connection established");
            }

            // Start new try-with-resources for data transfer
            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                // Continue with the rest of the connection handling
                String connectionConfirmation = in.readLine();
                if (!"CONNECTED".equals(connectionConfirmation)) {
                    throw new RuntimeException("Did not receive proper connection confirmation from Ghidra script");
                }
                LOGGER.info("Ghidra script confirmed connection, beginning analysis");

                LOGGER.info("[SOCKET] Reading class data from Ghidra script...");
                long readStart = System.currentTimeMillis();
                String line;
                StringBuilder classDataBuilder = new StringBuilder();
                while ((line = in.readLine()) != null && !line.equals("END_CLASS_DATA")) {
                    classDataBuilder.append(line).append("\n");
                }
                if (line == null) {
                    LOGGER.severe("[SOCKET] Connection lost while reading class data (received " + classDataBuilder.length() + " chars)");
                    throw new RuntimeException("Ghidra script disconnected during class data transfer");
                }
                LOGGER.info("[SOCKET] Class data received: " + classDataBuilder.length() + " chars in " + (System.currentTimeMillis() - readStart) + "ms");

                readStart = System.currentTimeMillis();
                LOGGER.info("[SOCKET] Reading Mach-O data...");
                StringBuilder machoDataBuilder = new StringBuilder();
                while ((line = in.readLine()) != null && !line.equals("END_MACHO_DATA")) {
                    machoDataBuilder.append(line).append("\n");
                }
                if (line == null) {
                    LOGGER.severe("[SOCKET] Connection lost while reading Macho data");
                    throw new RuntimeException("Ghidra script disconnected during Macho data transfer");
                }
                LOGGER.info("[SOCKET] Macho data received: " + machoDataBuilder.length() + " chars in " + (System.currentTimeMillis() - readStart) + "ms");

                readStart = System.currentTimeMillis();
                LOGGER.info("[SOCKET] Reading function decompilation data (this may take a while for large binaries)...");
                StringBuilder functionDataBuilder = new StringBuilder();
                int functionLineCount = 0;
                while ((line = in.readLine()) != null && !line.equals("END_DATA")) {
                    functionDataBuilder.append(line).append("\n");
                    functionLineCount++;
                    if (functionLineCount % 10000 == 0) {
                        LOGGER.info("[SOCKET] ... received " + functionLineCount + " lines of function data so far (" + (functionDataBuilder.length() / 1024) + " KB)");
                    }
                }
                if (line == null) {
                    LOGGER.severe("[SOCKET] Connection lost while reading function data after " + functionLineCount + " lines");
                    throw new RuntimeException("Ghidra script disconnected during function data transfer");
                }
                LOGGER.info("[SOCKET] Function data received: " + functionDataBuilder.length() + " chars, " + functionLineCount + " lines in " + (System.currentTimeMillis() - readStart) + "ms");

                readStart = System.currentTimeMillis();
                LOGGER.info("[SOCKET] Reading string data...");
                StringBuilder stringDataBuilder = new StringBuilder();
                while ((line = in.readLine()) != null && !line.equals("END_STRING_DATA")) {
                    stringDataBuilder.append(line).append("\n");
                }
                if (line == null) {
                    LOGGER.severe("[SOCKET] Connection lost while reading string data");
                    throw new RuntimeException("Ghidra script disconnected during string data transfer");
                }
                LOGGER.info("[SOCKET] String data received: " + stringDataBuilder.length() + " chars in " + (System.currentTimeMillis() - readStart) + "ms");

                // Process and store the received data
                LOGGER.info("[PARSE] Parsing JSON data...");
                long parseStart = System.currentTimeMillis();
                JSONArray classData;
                JSONArray functionData;
                JSONArray stringData;
                try {
                    classData = new JSONArray(classDataBuilder.toString());
                    LOGGER.info("[PARSE] Class data parsed: " + classData.length() + " entries");
                } catch (Exception e) {
                    LOGGER.severe("[PARSE] Failed to parse class data JSON (" + classDataBuilder.length() + " chars): " + e.getMessage());
                    LOGGER.severe("[PARSE] First 500 chars: " + classDataBuilder.substring(0, Math.min(500, classDataBuilder.length())));
                    throw e;
                }
                try {
                    functionData = new JSONArray(functionDataBuilder.toString());
                    LOGGER.info("[PARSE] Function data parsed: " + functionData.length() + " entries");
                } catch (Exception e) {
                    LOGGER.severe("[PARSE] Failed to parse function data JSON (" + functionDataBuilder.length() + " chars): " + e.getMessage());
                    LOGGER.severe("[PARSE] First 500 chars: " + functionDataBuilder.substring(0, Math.min(500, functionDataBuilder.length())));
                    throw e;
                }
                try {
                    stringData = new JSONArray(stringDataBuilder.toString());
                    LOGGER.info("[PARSE] String data parsed: " + stringData.length() + " entries");
                } catch (Exception e) {
                    LOGGER.severe("[PARSE] Failed to parse string data JSON (" + stringDataBuilder.length() + " chars): " + e.getMessage());
                    throw e;
                }
                LOGGER.info("[PARSE] All JSON parsed in " + (System.currentTimeMillis() - parseStart) + "ms: " + classData.length() + " classes, " + functionData.length() + " functions, " + stringData.length() + " strings");
                
                // Process both class and function data together
                Map<String, JSONArray> classToFunctions = new HashMap<>();
                Map<String, String> classNameMapping = new HashMap<>();

                // First pass: organize functions by class and demangle class names
                // Use parallelStream to process functionData in parallel
                ArrayList<SQLiteDBHandler.DecompilationResult> decompilationResults = new ArrayList<>();
                ArrayList<SyntaxParser> syntaxParsers = new ArrayList<>();

                functionData.toList().parallelStream().forEach(obj -> {
                    JSONObject functionObj = new JSONObject((Map<?, ?>) obj);
                    String functionName = functionObj.getString("FunctionName");
                    String className = functionObj.getString("ClassName");
                    String decompiledCode = functionObj.getString("DecompiledCode");

                    // For Swift binaries, get the class name from the function name
                    if (!config.isMac() && targetMacho.isSwift() && functionName.startsWith("_$s")) {
                        DemangleSwift.DemangledName demangledName = DemangleSwift.demangleSwiftName(functionName);
                        if (demangledName != null) {
                            LOGGER.info("Demangled function name from " + functionName + " to " + demangledName.fullMethodName);
                            className = demangledName.className;
                            functionName = demangledName.fullMethodName;
                            LOGGER.info("Using class name from demangled function: " + className);
                        } else {
                            LOGGER.warning("Failed to demangle Swift symbol: " + functionName);
                        }
                    }

                    // Replace empty class name with "Global" after demangling
                    if (className == null || className.trim().isEmpty()) {
                        className = "Global";
                    }

                    // Check if this class should be treated as a library
                    final String finalClassName = className;
                    boolean isLibrary = activeLibraries.stream()
                            .anyMatch(library -> finalClassName.startsWith(library));

                    if (!isLibrary) {
                        // Process and store the decompiled code only for non-library classes
                        decompiledCode = decompiledCode.replaceAll("/\\*.*\\*/", "");  // Remove Ghidra comments

                        // Add headers with the correct class name
                        if (!decompiledCode.trim().startsWith("// Class:") && !decompiledCode.trim().startsWith("// Function:")) {
                            StringBuilder contentBuilder = new StringBuilder();
                            contentBuilder.append("// Class: ").append(className).append("\n");
                            contentBuilder.append("// Function: ").append(functionName).append("\n\n");
                            contentBuilder.append(decompiledCode.trim());
                            decompiledCode = contentBuilder.toString();
                        }

                        String message = "Storing decompilation for " + className + "::" + functionName;
                        LOGGER.info(message);
                        if (consoleOutputCallback != null) {
                            consoleOutputCallback.accept(message);
                        }

                        // Store function decompilation with the correct class name and executable name
                        synchronized (decompilationResults) {
                            decompilationResults.add(new SQLiteDBHandler.DecompilationResult(functionName, className, decompiledCode, targetMacho.getMachoExecutableName()));
                        }
                        if (decompiledCode != null && !decompiledCode.trim().isEmpty()) {
                            // Parse the decompiled code for syntax information
                            SyntaxParser syntaxParser = new SyntaxParser(targetMacho.getMachoExecutableName());
                            syntaxParser.setContext(functionName, className);
                            syntaxParser.collectCrossReferences(decompiledCode);
                            synchronized (syntaxParsers) {
                                syntaxParsers.add(syntaxParser);
                            }
                        }

                        // Add to class functions map
                        synchronized (classToFunctions) {
                            classToFunctions.computeIfAbsent(className, k -> new JSONArray())
                                            .put(functionName);
                        }
                    } else {
                        // For library functions, combine class and function names and store under "Libraries"
                        String libraryFunctionName = className + "::" + functionName;
                        String message = "Storing library function: " + libraryFunctionName;
                        LOGGER.info(message);
                        if (consoleOutputCallback != null) {
                            consoleOutputCallback.accept(message);
                        }
                        functionName = libraryFunctionName;

                        // Store the mapping of original class name to "Libraries"
                        synchronized (classNameMapping) {
                            classNameMapping.put(className, "Libraries");
                        }


                        synchronized (decompilationResults) {
                            decompilationResults.add(new SQLiteDBHandler.DecompilationResult(libraryFunctionName, "Libraries", targetMacho.getMachoExecutableName(), targetMacho.getMachoExecutableName()));
                        }

                        // Add to class functions map under "Libraries"
                        synchronized (classToFunctions) {
                            classToFunctions.computeIfAbsent("Libraries", k -> new JSONArray())
                                            .put(libraryFunctionName);
                        }
                    }
                });

                ArrayList<SyntaxParser.TypeInfoResult> typeInfoResults = new ArrayList<>();
                ArrayList<SyntaxParser.FunctionRefResult> functionRefResults = new ArrayList<>();
                ArrayList<SyntaxParser.VariableRefResult> varRefs = new ArrayList<>();
                for (SyntaxParser parser : syntaxParsers) {
                    typeInfoResults.addAll(parser.getTypeInfoResults());
                    functionRefResults.addAll(parser.getFunctionRefResults());
                    varRefs.addAll(parser.getVariableRefResults());
                }
                dbHandler.insertFunctionDecompilations(decompilationResults);
                dbHandler.insertTypeInformations(typeInfoResults);
                dbHandler.insertFunctionReferences(functionRefResults);
                dbHandler.insertLocalVariableReferences(varRefs);

                // Store class data for all classes (including libraries)
                for (Map.Entry<String, JSONArray> entry : classToFunctions.entrySet()) {
                    String className = entry.getKey();
                    JSONArray functions = entry.getValue();
                    LOGGER.info("Inserting class: " + className + " with " + functions.length() + " functions");
                    dbHandler.insertClass(className, functions.toString(), targetMacho.getMachoExecutableName());
                }

                // Process string data
                LOGGER.info("[DB] Processing " + stringData.length() + " strings from Ghidra analysis");

                for (int i = 0; i < stringData.length(); i++) {
                    JSONObject stringObj = stringData.getJSONObject(i);
                    String address = stringObj.getString("address");
                    String value = stringObj.getString("value");
                    String segment = stringObj.getString("segment");
                    String label = stringObj.getString("label");
                    if (i < 5 || i % 1000 == 0) {
                        LOGGER.info("[DB] Inserting string [" + i + "/" + stringData.length() + "]: " + value);
                    }
                    dbHandler.insertMachoString(address, value, segment, label, targetMacho.getMachoExecutableName());
                }

                // Final verification
                LOGGER.info("=== ANALYSIS SUMMARY ===");
                LOGGER.info("[RESULT] Classes stored: " + classToFunctions.size());
                LOGGER.info("[RESULT] Functions decompiled: " + decompilationResults.size());
                LOGGER.info("[RESULT] Strings extracted: " + stringData.length());
                LOGGER.info("[RESULT] Type info entries: " + typeInfoResults.size());
                LOGGER.info("[RESULT] Function references: " + functionRefResults.size());
                LOGGER.info("[RESULT] Variable references: " + varRefs.size());
                boolean hasData = dbHandler.hasAnalysisData();
                LOGGER.info("[RESULT] DB verification - hasAnalysisData: " + hasData);
                if (!hasData) {
                    LOGGER.severe("[RESULT] WARNING: Analysis completed but DB appears empty! Data may not have been committed.");
                }
                LOGGER.info("=== END ANALYSIS SUMMARY ===");
            }

            process.waitFor();
            LOGGER.info("Ghidra analysis completed successfully");

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during Ghidra decompilation", e);
            throw new RuntimeException("Ghidra decompilation failed: " + e.getMessage(), e);
        }
    }    

    private String getAnalyzeHeadlessPath() {
        String analyzeHeadless = Paths.get(config.getGhidraPath(), "support", "analyzeHeadless").toString();
        if (config.isWindows()) {
            analyzeHeadless += ".bat";
        }
        LOGGER.info("Using analyzeHeadless path: " + analyzeHeadless);
        return analyzeHeadless;
    }

}
