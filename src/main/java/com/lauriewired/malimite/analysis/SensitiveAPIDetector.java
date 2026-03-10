package com.lauriewired.malimite.analysis;

import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects sensitive API calls in decompiled iOS/macOS code and Mach-O strings.
 * Categorizes findings by risk level and type.
 */
public class SensitiveAPIDetector {
    private static final Logger LOGGER = Logger.getLogger(SensitiveAPIDetector.class.getName());

    public static class Finding {
        public String apiName;
        public String category;
        public String riskLevel; // "critical", "high", "medium", "low"
        public String callerFunction;
        public String callerClass;
        public String matchedPattern;
        public String context; // surrounding code snippet

        public Finding(String apiName, String category, String riskLevel,
                       String callerFunction, String callerClass,
                       String matchedPattern, String context) {
            this.apiName = apiName;
            this.category = category;
            this.riskLevel = riskLevel;
            this.callerFunction = callerFunction;
            this.callerClass = callerClass;
            this.matchedPattern = matchedPattern;
            this.context = context;
        }

        public Map<String, String> toMap() {
            Map<String, String> map = new LinkedHashMap<>();
            map.put("apiName", apiName);
            map.put("category", category);
            map.put("riskLevel", riskLevel);
            map.put("callerFunction", callerFunction);
            map.put("callerClass", callerClass);
            map.put("matchedPattern", matchedPattern);
            map.put("context", context);
            return map;
        }
    }

    private static class APIPattern {
        String name;
        String regex;
        String category;
        String riskLevel;
        Pattern compiled;

        APIPattern(String name, String regex, String category, String riskLevel) {
            this.name = name;
            this.regex = regex;
            this.category = category;
            this.riskLevel = riskLevel;
            this.compiled = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        }
    }

    private static final List<APIPattern> PATTERNS = new ArrayList<>();

    static {
        // === JavaScript Bridge (Critical) ===
        p("evaluateJavaScript",      "evaluateJavaScript",                  "javascript_bridge", "critical");
        p("WKScriptMessage",         "WKScriptMessage",                     "javascript_bridge", "critical");
        p("addScriptMessageHandler", "addScriptMessageHandler",             "javascript_bridge", "critical");
        p("JavascriptBridge",        "(?i)javascript\\s*bridge",            "javascript_bridge", "critical");
        p("callAsyncJavaScript",     "callAsyncJavaScript",                 "javascript_bridge", "high");
        p("WKUserScript",            "WKUserScript",                        "javascript_bridge", "high");
        p("JSContext",               "JSContext",                           "javascript_bridge", "high");
        p("JSValue",                 "JSValue",                             "javascript_bridge", "medium");

        // === Network ===
        p("NSURLSession",            "NSURLSession|URLSession",             "network", "medium");
        p("NSURLConnection",         "NSURLConnection",                     "network", "medium");
        p("CFNetwork",               "CFNetwork|CFHTTPMessage",             "network", "medium");
        p("allowsArbitraryLoads",    "allowsArbitraryLoads",               "network", "high");
        p("TLS/SSL bypass",          "setAllowsAnyHTTPSCertificate|ServerTrust|kSSLSessionConfig", "network", "critical");
        p("HTTP (non-HTTPS)",        "http://[^\\s\"']+",                   "network", "medium");

        // === Crypto ===
        p("CCCrypt",                 "CCCrypt|CommonCrypto",                "crypto", "high");
        p("SecKeyEncrypt",           "SecKey(?:Encrypt|Decrypt|CreateWithData)", "crypto", "high");
        p("Hardcoded IV/Key",        "(?:iv|key|secret)\\s*=\\s*[\"'][0-9a-fA-F]{16,}[\"']", "crypto", "critical");
        p("MD5/SHA1 (weak)",         "CC_MD5|CC_SHA1|kCCHmacAlgMD5|kCCHmacAlgSHA1", "crypto", "high");
        p("ECB Mode",                "kCCOptionECBMode",                    "crypto", "high");

        // === Keychain ===
        p("SecItemAdd",              "SecItemAdd|SecItemCopyMatching|SecItemUpdate|SecItemDelete", "keychain", "medium");
        p("kSecAttrAccessible",      "kSecAttrAccessible(?:Always|WhenUnlocked|AfterFirstUnlock)", "keychain", "medium");

        // === Clipboard ===
        p("UIPasteboard",            "UIPasteboard|generalPasteboard",      "clipboard", "high");

        // === File I/O ===
        p("NSFileManager",           "NSFileManager|FileManager",           "file_io", "low");
        p("sqlite3_open",            "sqlite3_open|sqlite3_exec",           "file_io", "medium");
        p("NSUserDefaults",          "NSUserDefaults|UserDefaults",         "file_io", "medium");
        p("Unprotected File",        "NSFileProtection(?:None|CompleteUntilFirstUserAuthentication)", "file_io", "high");

        // === IPC / URL Scheme ===
        p("openURL",                 "openURL|canOpenURL",                  "ipc_url_scheme", "medium");
        p("handleOpenURL",           "handleOpenURL|application.*openURL",  "ipc_url_scheme", "high");
        p("Custom URL Scheme",       "registerScheme|URLScheme",            "ipc_url_scheme", "medium");
        p("Universal Links",         "userActivity.*webpageURL|continue.*userActivity", "ipc_url_scheme", "medium");
        p("App Groups",              "appGroupUserDefaults|suiteName",      "ipc_url_scheme", "medium");

        // === Dynamic Loading ===
        p("dlopen",                  "\\bdlopen\\b|\\bdlsym\\b",           "dynamic_loading", "critical");
        p("NSClassFromString",       "NSClassFromString|NSSelectorFromString", "dynamic_loading", "high");
        p("performSelector",         "performSelector",                     "dynamic_loading", "high");
        p("objc_msgSend (dynamic)",  "objc_msgSend",                       "dynamic_loading", "low");

        // === Privacy ===
        p("Location",                "CLLocationManager|requestWhenInUseAuthorization|requestAlwaysAuthorization", "privacy", "medium");
        p("Camera",                  "AVCaptureDevice|requestAccess.*video", "privacy", "medium");
        p("Contacts",                "CNContactStore|requestAccess.*contacts", "privacy", "medium");
        p("Photos",                  "PHPhotoLibrary|requestAuthorization", "privacy", "medium");
        p("Microphone",              "AVAudioSession|requestRecordPermission", "privacy", "medium");

        // === Jailbreak Detection ===
        p("Jailbreak Check (Cydia)", "Cydia|/Applications/Cydia\\.app",     "jailbreak_detection", "low");
        p("Jailbreak Check (paths)", "/private/var/lib/apt|/bin/bash|/usr/sbin/sshd", "jailbreak_detection", "low");
        p("Jailbreak Check (fork)",  "\\bfork\\(\\)|\\bsystem\\(",         "jailbreak_detection", "medium");

        // === Hardcoded Secrets ===
        p("API Key Pattern",         "(?:api[_-]?key|apikey)\\s*[:=]\\s*[\"'][A-Za-z0-9_\\-]{20,}[\"']", "hardcoded_secret", "critical");
        p("Bearer Token",            "Bearer\\s+[A-Za-z0-9_\\-\\.]{20,}",  "hardcoded_secret", "critical");
        p("Private Key",             "-----BEGIN (?:RSA |EC )?PRIVATE KEY", "hardcoded_secret", "critical");
        p("AWS Key",                 "AKIA[0-9A-Z]{16}",                   "hardcoded_secret", "critical");
        p("Password Pattern",        "(?:password|passwd|pwd)\\s*[:=]\\s*[\"'][^\"']{4,}[\"']", "hardcoded_secret", "high");

        // === WebView Security ===
        p("allowFileAccess",         "allowFileAccess|allowingReadAccessToURL", "webview_security", "high");
        p("javaScriptEnabled",       "javaScriptEnabled|isJavaScriptEnabled",  "webview_security", "medium");
        p("allowUniversalAccess",    "allowUniversalAccessFromFileURLs",    "webview_security", "critical");
    }

    private static void p(String name, String regex, String category, String risk) {
        PATTERNS.add(new APIPattern(name, regex, category, risk));
    }

    /**
     * Scan a single function's decompiled code for sensitive API calls.
     */
    public static List<Finding> scanFunction(String functionName, String className, String decompiledCode) {
        List<Finding> findings = new ArrayList<>();
        if (decompiledCode == null || decompiledCode.isEmpty()) return findings;

        for (APIPattern pattern : PATTERNS) {
            Matcher matcher = pattern.compiled.matcher(decompiledCode);
            while (matcher.find()) {
                String matched = matcher.group();
                // Extract a snippet of context around the match
                int start = Math.max(0, matcher.start() - 40);
                int end = Math.min(decompiledCode.length(), matcher.end() + 40);
                String context = decompiledCode.substring(start, end).replaceAll("\\s+", " ").trim();

                findings.add(new Finding(
                    pattern.name, pattern.category, pattern.riskLevel,
                    functionName, className, matched, context
                ));
            }
        }
        return findings;
    }

    /**
     * Scan a Mach-O string value for sensitive patterns.
     */
    public static List<Finding> scanString(String stringValue, String address) {
        List<Finding> findings = new ArrayList<>();
        if (stringValue == null || stringValue.isEmpty()) return findings;

        for (APIPattern pattern : PATTERNS) {
            Matcher matcher = pattern.compiled.matcher(stringValue);
            while (matcher.find()) {
                findings.add(new Finding(
                    pattern.name, pattern.category, pattern.riskLevel,
                    "string@" + address, "MachoStrings",
                    matcher.group(), stringValue.length() > 120 ? stringValue.substring(0, 120) + "..." : stringValue
                ));
            }
        }
        return findings;
    }

    /**
     * Get all pattern categories for documentation.
     */
    public static Map<String, List<String>> getPatternCategories() {
        Map<String, List<String>> categories = new LinkedHashMap<>();
        for (APIPattern p : PATTERNS) {
            categories.computeIfAbsent(p.category, k -> new ArrayList<>()).add(p.name + " [" + p.riskLevel + "]");
        }
        return categories;
    }
}
