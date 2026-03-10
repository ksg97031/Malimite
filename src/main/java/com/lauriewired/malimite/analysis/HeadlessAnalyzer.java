package com.lauriewired.malimite.analysis;

import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.decompile.GhidraProject;
import com.lauriewired.malimite.files.Macho;

import com.lauriewired.malimite.utils.FileProcessing;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Headless analyzer for CLI mode.
 * Runs Ghidra decompilation and produces structured JSON output
 * without any GUI dependencies.
 */
public class HeadlessAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(HeadlessAnalyzer.class.getName());

    private final Config config;
    private final String inputFilePath;
    private final String outputDir;
    private SQLiteDBHandler dbHandler;
    private Macho projectMacho;
    private String projectDirectoryPath;
    private String executableName;

    public HeadlessAnalyzer(Config config, String inputFilePath, String outputDir) {
        this.config = config;
        // Resolve to absolute paths to avoid null parent issues
        this.inputFilePath = new File(inputFilePath).getAbsolutePath();
        this.outputDir = new File(outputDir).getAbsolutePath();
    }

    /**
     * Run the full headless analysis pipeline.
     */
    public void run() throws Exception {
        LOGGER.info("[HEADLESS] Starting analysis: " + inputFilePath);
        long startTime = System.currentTimeMillis();

        // Step 1: Extract and prepare
        extractAndPrepare();

        // Step 2: Load/Run Ghidra analysis
        loadOrAnalyze();

        // Step 3: Create output directory
        Path outPath = Paths.get(outputDir);
        Files.createDirectories(outPath);

        // Step 4: Generate all outputs
        LOGGER.info("[HEADLESS] Generating analysis outputs to: " + outputDir);

        writeMeta(outPath);
        writeClasses(outPath);
        writeEntrypoints(outPath);
        writeSensitiveAPIs(outPath);
        writeURLsAndEndpoints(outPath);
        writeCallGraph(outPath);
        writeStringsFiltered(outPath);
        writeBinarySecurity(outPath);
        dumpDecompiledCode(outPath);

        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        LOGGER.info("[HEADLESS] Analysis complete in " + elapsed + "s. Output: " + outputDir);

        // Print summary to stdout
        printSummary();
    }

    private void extractAndPrepare() throws Exception {
        File inputFile = new File(inputFilePath);
        if (!inputFile.exists()) {
            throw new FileNotFoundException("Input file not found: " + inputFilePath);
        }

        // Parse Info.plist to get executable name
        executableName = findExecutableName(inputFilePath);
        LOGGER.info("[HEADLESS] Executable name: " + executableName);

        // Extract Mach-O
        FileProcessing.setConfig(config);
        projectDirectoryPath = FileProcessing.extractMachoToProjectDirectory(
            inputFilePath, executableName, config.getConfigDirectory());
        FileProcessing.openProject(inputFilePath, projectDirectoryPath,
            executableName, config.getConfigDirectory(), false);

        // Load Mach-O
        String execPath = projectDirectoryPath + File.separator + executableName;
        projectMacho = new Macho(execPath, projectDirectoryPath, executableName);

        // Handle universal binary - auto-select ARM64
        if (projectMacho.isUniversalBinary()) {
            List<String> archs = projectMacho.getArchitectureStrings();
            String arm64 = archs.stream().filter(a -> a.contains("ARM64")).findFirst().orElse(archs.get(0));
            LOGGER.info("[HEADLESS] Auto-selecting architecture: " + arm64);
            projectMacho.processUniversalMacho(arm64);
        }
    }

    private void loadOrAnalyze() throws Exception {
        String baseName = new File(inputFilePath).getName();
        int dot = baseName.lastIndexOf('.');
        if (dot > 0) baseName = baseName.substring(0, dot);
        String dbFilePath = projectDirectoryPath + File.separator + baseName + "_malimite.db";

        File dbFile = new File(dbFilePath);
        boolean needsAnalysis = !dbFile.exists();

        if (dbFile.exists()) {
            dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, baseName + "_malimite.db");
            if (!dbHandler.hasAnalysisData()) {
                LOGGER.warning("[HEADLESS] Empty DB found, re-analyzing...");
                try { dbHandler.GetTransaction().close(); } catch (Exception e) { /* ignore */ }
                dbFile.delete();
                needsAnalysis = true;
            }
        }

        if (needsAnalysis) {
            if (config.getGhidraPath() == null || config.getGhidraPath().trim().isEmpty()) {
                throw new IllegalStateException("Ghidra path not configured. Set it in malimite.properties.");
            }

            dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, baseName + "_malimite.db");
            String execPath = projectDirectoryPath + File.separator + executableName;
            GhidraProject ghidra = new GhidraProject(executableName, execPath, config, dbHandler,
                message -> LOGGER.info("[GHIDRA] " + message));
            ghidra.decompileMacho(execPath, projectDirectoryPath, projectMacho, false);
        } else {
            LOGGER.info("[HEADLESS] Using existing analysis database");
        }
    }

    // === Output Generators ===

    private void writeMeta(Path outPath) throws IOException {
        JSONObject meta = new JSONObject();
        meta.put("inputFile", inputFilePath);
        meta.put("executableName", executableName);
        meta.put("isSwift", projectMacho.isSwift());
        meta.put("isUniversal", projectMacho.isUniversalBinary());
        meta.put("isEncrypted", projectMacho.isEncrypted());
        meta.put("encryptionSummary", projectMacho.getEncryptionSummary());
        meta.put("fileSize", new File(inputFilePath).length());

        // Count stats from DB
        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Classes");
            meta.put("classCount", rs.next() ? rs.getInt(1) : 0);
            rs = stmt.executeQuery("SELECT COUNT(*) FROM Functions");
            meta.put("functionCount", rs.next() ? rs.getInt(1) : 0);
            rs = stmt.executeQuery("SELECT COUNT(*) FROM Functions WHERE DecompilationCode NOT LIKE '%halt_baddata%' AND LENGTH(DecompilationCode) > 100");
            meta.put("readableFunctionCount", rs.next() ? rs.getInt(1) : 0);
            rs = stmt.executeQuery("SELECT COUNT(*) FROM MachoStrings");
            meta.put("stringCount", rs.next() ? rs.getInt(1) : 0);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error getting DB stats", e);
        }

        writeJSON(outPath.resolve("meta.json"), meta);
        LOGGER.info("[HEADLESS] meta.json written");
    }

    private void writeClasses(Path outPath) throws IOException {
        JSONArray classes = new JSONArray();
        Map<String, List<String>> classMap = dbHandler.getAllClassesAndFunctions();
        for (Map.Entry<String, List<String>> entry : classMap.entrySet()) {
            JSONObject cls = new JSONObject();
            cls.put("className", entry.getKey());
            cls.put("functions", new JSONArray(entry.getValue()));
            cls.put("functionCount", entry.getValue().size());
            classes.put(cls);
        }
        writeJSON(outPath.resolve("classes.json"), classes);
        LOGGER.info("[HEADLESS] classes.json written (" + classMap.size() + " classes)");
    }

    private void writeEntrypoints(Path outPath) throws IOException {
        String[] entrypointPatterns = {
            "applicationDidFinishLaunching", "application:didFinishLaunchingWithOptions:",
            "applicationWillTerminate", "applicationDidBecomeActive",
            "applicationWillResignActive", "applicationDidEnterBackground",
            "applicationWillEnterForeground",
            "scene:willConnectToSession:options:", "sceneDidDisconnect:",
            "sceneDidBecomeActive:", "sceneWillResignActive:",
            "sceneWillEnterForeground:", "sceneDidEnterBackground:",
            "application:didRegisterForRemoteNotificationsWithDeviceToken:",
            "application:didReceiveRemoteNotification:fetchCompletionHandler:",
            "application:openURL:options:", "application:handleOpenURL:",
            "application:continue:restorationHandler:",
            "viewDidLoad", "loadView", "main",
            "userContentController:didReceiveScriptMessage:",
            "webView:decidePolicyForNavigationAction:",
            "webView:didFinishNavigation:"
        };

        JSONArray entrypoints = new JSONArray();
        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            for (String pattern : entrypointPatterns) {
                String safePat = pattern.replace("'", "''");
                ResultSet rs = stmt.executeQuery(
                    "SELECT FunctionName, ParentClass, LENGTH(DecompilationCode) as codeLen, " +
                    "CASE WHEN DecompilationCode LIKE '%halt_baddata%' THEN 'encrypted' ELSE 'readable' END as status " +
                    "FROM Functions WHERE FunctionName LIKE '%" + safePat + "%'");
                while (rs.next()) {
                    JSONObject ep = new JSONObject();
                    ep.put("pattern", pattern);
                    ep.put("functionName", rs.getString("FunctionName"));
                    ep.put("className", rs.getString("ParentClass"));
                    ep.put("codeLength", rs.getInt("codeLen"));
                    ep.put("status", rs.getString("status"));
                    entrypoints.put(ep);
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error querying entrypoints", e);
        }
        writeJSON(outPath.resolve("entrypoints.json"), entrypoints);
        LOGGER.info("[HEADLESS] entrypoints.json written (" + entrypoints.length() + " entrypoints)");
    }

    private void writeSensitiveAPIs(Path outPath) throws IOException {
        List<SensitiveAPIDetector.Finding> allFindings = new ArrayList<>();

        // Scan decompiled functions
        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT FunctionName, ParentClass, DecompilationCode FROM Functions " +
                "WHERE DecompilationCode NOT LIKE '%halt_baddata%' AND LENGTH(DecompilationCode) > 50");
            while (rs.next()) {
                List<SensitiveAPIDetector.Finding> findings = SensitiveAPIDetector.scanFunction(
                    rs.getString("FunctionName"),
                    rs.getString("ParentClass"),
                    rs.getString("DecompilationCode"));
                allFindings.addAll(findings);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error scanning functions", e);
        }

        // Scan Mach-O strings
        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery("SELECT address, value FROM MachoStrings");
            while (rs.next()) {
                List<SensitiveAPIDetector.Finding> findings = SensitiveAPIDetector.scanString(
                    rs.getString("value"), rs.getString("address"));
                allFindings.addAll(findings);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error scanning strings", e);
        }

        // Deduplicate by unique key (api+caller+matched)
        Map<String, SensitiveAPIDetector.Finding> deduped = new LinkedHashMap<>();
        for (SensitiveAPIDetector.Finding f : allFindings) {
            String key = f.apiName + "|" + f.callerFunction + "|" + f.callerClass + "|" + f.matchedPattern;
            deduped.putIfAbsent(key, f);
        }

        // Build JSON with category grouping
        JSONObject output = new JSONObject();
        JSONObject summary = new JSONObject();
        Map<String, Integer> byCat = new LinkedHashMap<>();
        Map<String, Integer> byRisk = new LinkedHashMap<>();

        JSONArray findingsArray = new JSONArray();
        for (SensitiveAPIDetector.Finding f : deduped.values()) {
            findingsArray.put(new JSONObject(f.toMap()));
            byCat.merge(f.category, 1, Integer::sum);
            byRisk.merge(f.riskLevel, 1, Integer::sum);
        }

        summary.put("totalFindings", deduped.size());
        summary.put("byCategory", new JSONObject(byCat));
        summary.put("byRiskLevel", new JSONObject(byRisk));
        output.put("summary", summary);
        output.put("findings", findingsArray);

        writeJSON(outPath.resolve("sensitive_apis.json"), output);
        LOGGER.info("[HEADLESS] sensitive_apis.json written (" + deduped.size() + " findings)");
    }

    private void writeURLsAndEndpoints(Path outPath) throws IOException {
        Pattern urlPattern = Pattern.compile(
            "(https?://[^\\s\"'<>\\]\\)}{]+)" +
            "|(\\w+://[^\\s\"'<>\\]\\)}{]+)"
        );

        JSONArray urls = new JSONArray();
        Set<String> seen = new HashSet<>();

        try {
            // From strings
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery("SELECT address, value FROM MachoStrings");
            while (rs.next()) {
                String value = rs.getString("value");
                Matcher m = urlPattern.matcher(value);
                while (m.find()) {
                    String url = m.group().replaceAll("[\"']$", "");
                    if (seen.add(url)) {
                        JSONObject entry = new JSONObject();
                        entry.put("url", url);
                        entry.put("type", classifyURL(url));
                        entry.put("source", "macho_string");
                        entry.put("address", rs.getString("address"));
                        urls.put(entry);
                    }
                }
            }

            // From decompiled code
            rs = stmt.executeQuery(
                "SELECT FunctionName, ParentClass, DecompilationCode FROM Functions " +
                "WHERE DecompilationCode NOT LIKE '%halt_baddata%' AND LENGTH(DecompilationCode) > 50");
            while (rs.next()) {
                Matcher m = urlPattern.matcher(rs.getString("DecompilationCode"));
                while (m.find()) {
                    String url = m.group().replaceAll("[\"']$", "");
                    if (seen.add(url)) {
                        JSONObject entry = new JSONObject();
                        entry.put("url", url);
                        entry.put("type", classifyURL(url));
                        entry.put("source", "decompiled_code");
                        entry.put("sourceFunction", rs.getString("FunctionName"));
                        entry.put("sourceClass", rs.getString("ParentClass"));
                        urls.put(entry);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error extracting URLs", e);
        }

        writeJSON(outPath.resolve("urls_endpoints.json"), urls);
        LOGGER.info("[HEADLESS] urls_endpoints.json written (" + urls.length() + " URLs)");
    }

    private void writeCallGraph(Path outPath) throws IOException {
        JSONArray graph = new JSONArray();
        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT sourceFunction, sourceClass, targetFunction, targetClass, lineNumber " +
                "FROM FunctionReferences ORDER BY sourceClass, sourceFunction");
            while (rs.next()) {
                JSONObject edge = new JSONObject();
                edge.put("from", rs.getString("sourceClass") + "::" + rs.getString("sourceFunction"));
                edge.put("to", rs.getString("targetClass") + "::" + rs.getString("targetFunction"));
                edge.put("sourceFunction", rs.getString("sourceFunction"));
                edge.put("sourceClass", rs.getString("sourceClass"));
                edge.put("targetFunction", rs.getString("targetFunction"));
                edge.put("targetClass", rs.getString("targetClass"));
                edge.put("lineNumber", rs.getInt("lineNumber"));
                graph.put(edge);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error building call graph", e);
        }
        writeJSON(outPath.resolve("call_graph.json"), graph);
        LOGGER.info("[HEADLESS] call_graph.json written (" + graph.length() + " edges)");
    }

    private void writeStringsFiltered(Path outPath) throws IOException {
        // Security-relevant string patterns
        Pattern[] securityPatterns = {
            Pattern.compile("(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|auth)"),
            Pattern.compile("(?i)(encrypt|decrypt|cipher|aes|rsa|hmac|hash|md5|sha)"),
            Pattern.compile("https?://"),
            Pattern.compile("(?i)(certificate|ssl|tls|pinning)"),
            Pattern.compile("(?i)(jailbreak|cydia|substrate|frida|debugger)"),
            Pattern.compile("(?i)(firebase|aws|azure|google[_-]?cloud)"),
            Pattern.compile("(?i)(oauth|bearer|jwt|saml)"),
            Pattern.compile("(?i)(inject|exploit|overflow|format[_-]?string)")
        };

        JSONArray filtered = new JSONArray();
        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery("SELECT address, value, segment, label FROM MachoStrings");
            while (rs.next()) {
                String value = rs.getString("value");
                for (Pattern p : securityPatterns) {
                    if (p.matcher(value).find()) {
                        JSONObject entry = new JSONObject();
                        entry.put("address", rs.getString("address"));
                        entry.put("value", value.length() > 200 ? value.substring(0, 200) + "..." : value);
                        entry.put("segment", rs.getString("segment"));
                        entry.put("label", rs.getString("label"));
                        filtered.put(entry);
                        break; // one match is enough
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error filtering strings", e);
        }
        writeJSON(outPath.resolve("strings_filtered.json"), filtered);
        LOGGER.info("[HEADLESS] strings_filtered.json written (" + filtered.length() + " security strings)");
    }

    private void writeBinarySecurity(Path outPath) throws IOException {
        JSONObject security = new JSONObject();

        // Encryption
        security.put("fairPlayEncrypted", projectMacho.isEncrypted());
        security.put("encryptionDetails", projectMacho.getEncryptionSummary());

        // Check for security features in strings
        boolean hasStackCanary = false;
        boolean hasARC = false;
        boolean hasPIE = false;

        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();

            // Stack canary
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM MachoStrings WHERE value LIKE '%__stack_chk_fail%'");
            hasStackCanary = rs.next() && rs.getInt(1) > 0;

            // ARC
            rs = stmt.executeQuery("SELECT COUNT(*) FROM MachoStrings WHERE value LIKE '%objc_release%' OR value LIKE '%objc_retain%'");
            hasARC = rs.next() && rs.getInt(1) > 0;

            // Check functions for security indicators
            rs = stmt.executeQuery("SELECT COUNT(*) FROM Functions WHERE FunctionName LIKE '%stack_chk%'");
            if (!hasStackCanary) hasStackCanary = rs.next() && rs.getInt(1) > 0;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error checking binary security", e);
        }

        security.put("stackCanary", hasStackCanary);
        security.put("arc", hasARC);
        security.put("swift", projectMacho.isSwift());

        writeJSON(outPath.resolve("binary_security.json"), security);
        LOGGER.info("[HEADLESS] binary_security.json written");
    }

    private void dumpDecompiledCode(Path outPath) throws IOException {
        Path decompiledDir = outPath.resolve("decompiled");
        Files.createDirectories(decompiledDir);

        int fileCount = 0;
        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT DISTINCT ParentClass FROM Functions " +
                "WHERE DecompilationCode NOT LIKE '%halt_baddata%' AND LENGTH(DecompilationCode) > 100");

            List<String> classes = new ArrayList<>();
            while (rs.next()) classes.add(rs.getString("ParentClass"));

            for (String className : classes) {
                StringBuilder code = new StringBuilder();
                code.append("// Class: ").append(className).append("\n\n");

                var pstmt = dbHandler.GetTransaction().prepareStatement(
                    "SELECT FunctionName, DecompilationCode FROM Functions " +
                    "WHERE ParentClass = ? AND DecompilationCode NOT LIKE '%halt_baddata%' " +
                    "AND LENGTH(DecompilationCode) > 100 ORDER BY FunctionName");
                pstmt.setString(1, className);
                ResultSet frs = pstmt.executeQuery();

                while (frs.next()) {
                    code.append(frs.getString("DecompilationCode")).append("\n\n");
                }

                String safeName = className.replaceAll("[^a-zA-Z0-9_\\-]", "_");
                Files.writeString(decompiledDir.resolve(safeName + ".c"), code.toString());
                fileCount++;
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error dumping decompiled code", e);
        }
        LOGGER.info("[HEADLESS] decompiled/ written (" + fileCount + " class files)");
    }

    // === Utilities ===

    private String findExecutableName(String ipaPath) throws Exception {
        // Search for Info.plist in the IPA to extract CFBundleExecutable
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(ipaPath))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                // Match Payload/XXX.app/Info.plist (top-level only)
                if (name.matches("Payload/[^/]+\\.app/Info.plist")) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int len;
                    while ((len = zis.read(buf)) > 0) baos.write(buf, 0, len);

                    com.dd.plist.NSObject plist = com.dd.plist.PropertyListParser.parse(baos.toByteArray());
                    if (plist instanceof com.dd.plist.NSDictionary) {
                        com.dd.plist.NSDictionary dict = (com.dd.plist.NSDictionary) plist;
                        return dict.objectForKey("CFBundleExecutable").toString();
                    }
                }
            }
        }
        throw new IllegalStateException("Could not find Info.plist in IPA: " + ipaPath);
    }

    private static String classifyURL(String url) {
        if (url.startsWith("http://") || url.startsWith("https://")) {
            if (url.contains("/api/") || url.contains("/v1/") || url.contains("/v2/") || url.contains("/v3/"))
                return "api_endpoint";
            return "web_url";
        }
        return "custom_scheme";
    }

    private static void writeJSON(Path path, Object json) throws IOException {
        String content;
        if (json instanceof JSONObject) {
            content = ((JSONObject) json).toString(2);
        } else if (json instanceof JSONArray) {
            content = ((JSONArray) json).toString(2);
        } else {
            content = json.toString();
        }
        Files.writeString(path, content);
    }

    private void printSummary() {
        System.out.println("\n=== Malimite Headless Analysis Complete ===");
        System.out.println("Input:     " + inputFilePath);
        System.out.println("Output:    " + outputDir);
        System.out.println("Encrypted: " + (projectMacho.isEncrypted() ? "YES (FairPlay DRM)" : "No"));
        System.out.println("Swift:     " + projectMacho.isSwift());

        try {
            Statement stmt = dbHandler.GetTransaction().createStatement();
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Classes");
            int classes = rs.next() ? rs.getInt(1) : 0;
            rs = stmt.executeQuery("SELECT COUNT(*) FROM Functions");
            int funcs = rs.next() ? rs.getInt(1) : 0;
            rs = stmt.executeQuery("SELECT COUNT(*) FROM Functions WHERE DecompilationCode NOT LIKE '%halt_baddata%' AND LENGTH(DecompilationCode) > 100");
            int readable = rs.next() ? rs.getInt(1) : 0;

            System.out.println("Classes:   " + classes);
            System.out.println("Functions: " + funcs + " (readable: " + readable + ")");
        } catch (Exception e) { /* ignore */ }

        System.out.println("\nOutput files:");
        try {
            Files.list(Paths.get(outputDir))
                .filter(p -> !Files.isDirectory(p))
                .sorted()
                .forEach(p -> {
                    try {
                        System.out.println("  " + p.getFileName() + " (" + Files.size(p) / 1024 + "KB)");
                    } catch (IOException e) { /* ignore */ }
                });
            Path decompiledDir = Paths.get(outputDir, "decompiled");
            if (Files.exists(decompiledDir)) {
                long count = Files.list(decompiledDir).count();
                System.out.println("  decompiled/ (" + count + " files)");
            }
        } catch (IOException e) { /* ignore */ }

        System.out.println("==========================================");
    }
}
