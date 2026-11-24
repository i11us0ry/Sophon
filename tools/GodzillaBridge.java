import core.ApplicationContext;
import core.imp.Cryption;
import core.imp.Payload;
import core.shell.ShellEntity;
import shells.channel.HttpRequestChannel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public final class GodzillaBridge {
    private GodzillaBridge() {
    }

    public static void main(String[] args) {
        System.setProperty("java.awt.headless", "true");
        if (args.length == 1 && "--list".equals(args[0])) {
            printCatalog();
            return;
        }
        if (args.length < 8) {
            printError("invalid_options", "configure", "missing Godzilla probe arguments", "");
            System.exit(2);
        }
        probe(args);
    }

    private static void probe(String[] args) {
        String url = args[0];
        String password = args[1];
        String secretKey = args[2];
        String payloadName = args[3];
        String cryptor = args[4];
        String encoding = args[5];
        int connectTimeout = parseTimeout(args[6]);
        int readTimeout = parseTimeout(args[7]);
        boolean verifyTls = args.length > 8 && Boolean.parseBoolean(args[8]);
        String headersEncoded = args.length > 9 ? args[9] : "";
        String keyFingerprint = "";

        try {
            if (!verifyTls) {
                disableTlsVerification();
            }
            ShellEntity shell = new ShellEntity();
            shell.setUrl(url);
            shell.setPassword(password);
            shell.setSecretKey(secretKey);
            shell.setPayload(payloadName);
            shell.setCryption(cryptor);
            shell.setEncoding(encoding);
            shell.setConnTimeout(connectTimeout);
            shell.setReadTimeout(readTimeout);
            shell.setMaxErrRetry(1);
            shell.setUseCache(false);
            applyHeaders(shell, headersEncoded);
            keyFingerprint = fingerprint(shell.getSecretKeyX());

            Payload payload = ApplicationContext.getPayload(payloadName);
            if (payload == null) {
                printError(
                    "protocol_error",
                    "configure",
                    "unsupported Godzilla payload: " + payloadName,
                    keyFingerprint
                );
                System.exit(1);
            }
            Cryption cryption = ApplicationContext.getCryption(payloadName, cryptor);
            if (cryption == null) {
                printError(
                    "protocol_error",
                    "configure",
                    "unsupported Godzilla cryptor: " + cryptor,
                    keyFingerprint
                );
                System.exit(1);
            }
            shell.setRequest(new HttpRequestChannel(shell));
            shell.setPayloadModel(payload);

            try {
                cryption.init(shell);
            } catch (Throwable error) {
                printError("protocol_error", "cryptor_init", describe(error), keyFingerprint);
                System.exit(1);
            }
            if (!cryption.check()) {
                printError(
                    "protocol_error",
                    "cryptor_check",
                    "Godzilla cryptor initialization failed",
                    keyFingerprint
                );
                System.exit(1);
            }

            try {
                payload.init(shell);
            } catch (Throwable error) {
                printError("protocol_error", "payload_init", describe(error), keyFingerprint);
                System.exit(1);
            }

            boolean tested;
            try {
                tested = payload.test();
            } catch (Throwable error) {
                printError("protocol_error", "payload_test", describe(error), keyFingerprint);
                System.exit(1);
                return;
            }
            if (!tested) {
                printError(
                    "protocol_error",
                    "payload_test",
                    "Godzilla payload test failed: no valid sessionId returned",
                    keyFingerprint
                );
                System.exit(1);
            }

            String sample;
            try {
                sample = payload.getBasicsInfo();
            } catch (Throwable error) {
                printError("protocol_error", "basics_info", describe(error), keyFingerprint);
                System.exit(1);
                return;
            }
            boolean alive = payload.isAlive();
            if (!alive) {
                printError(
                    "protocol_error",
                    "alive",
                    "payload returned no active session",
                    keyFingerprint
                );
                System.exit(1);
            }
            if (sample == null) {
                sample = "";
            }
            System.out.print("{\"connected\":true,\"status\":\"connected\",\"phase\":\"alive\",");
            System.out.print("\"key_fingerprint\":\"");
            System.out.print(jsonEscape(keyFingerprint));
            System.out.print("\",\"alive\":true,\"payload\":\"");
            System.out.print(jsonEscape(payloadName));
            System.out.print("\",\"cryptor\":\"");
            System.out.print(jsonEscape(cryptor));
            System.out.print("\",\"sample\":\"");
            System.out.print(jsonEscape(sample));
            System.out.println("\"}");
        } catch (Throwable error) {
            printError("protocol_error", "configure", describe(error), keyFingerprint);
            System.exit(1);
        }
    }

    private static void printCatalog() {
        try {
            String[] payloads = ApplicationContext.getAllPayload();
            Arrays.sort(payloads);
            StringBuilder json = new StringBuilder("{\"status\":\"ok\",\"payloads\":[");
            for (int payloadIndex = 0; payloadIndex < payloads.length; payloadIndex++) {
                String payload = payloads[payloadIndex];
                String[] cryptors = ApplicationContext.getAllCryption(payload);
                Arrays.sort(cryptors);
                if (payloadIndex > 0) {
                    json.append(",");
                }
                json.append("{\"payload\":\"");
                json.append(jsonEscape(payload));
                json.append("\",\"cryptors\":[");
                for (int cryptorIndex = 0; cryptorIndex < cryptors.length; cryptorIndex++) {
                    if (cryptorIndex > 0) {
                        json.append(",");
                    }
                    json.append("\"");
                    json.append(jsonEscape(cryptors[cryptorIndex]));
                    json.append("\"");
                }
                json.append("]}");
            }
            json.append("]}");
            System.out.println(json);
        } catch (Throwable error) {
            printError("official_unavailable", "catalog", describe(error), "");
            System.exit(1);
        }
    }

    private static int parseTimeout(String value) {
        try {
            return Math.max(1, Math.min(120, Integer.parseInt(value)));
        } catch (NumberFormatException ignored) {
            return 10;
        }
    }

    private static void applyHeaders(ShellEntity shell, String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return;
        }
        LinkedHashMap<String, LinkedList<String>> headers = new LinkedHashMap<>();
        String raw = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        for (String line : raw.split("\\n")) {
            int separator = line.indexOf(':');
            if (separator <= 0) {
                continue;
            }
            String name = line.substring(0, separator).trim();
            String value = line.substring(separator + 1).trim();
            if (name.isEmpty() || value.isEmpty()) {
                continue;
            }
            headers.computeIfAbsent(name, ignored -> new LinkedList<>()).add(value);
        }
        if (!headers.isEmpty()) {
            shell.setHeaders(headers);
        }
    }

    private static void disableTlsVerification() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        HostnameVerifier acceptAll = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(acceptAll);
    }

    private static String fingerprint(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte item : hash) {
                builder.append(String.format("%02x", item & 0xff));
            }
            return builder.substring(0, 16);
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String describe(Throwable error) {
        String message = error.getMessage();
        return error.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }

    private static void printError(
        String status,
        String phase,
        String message,
        String keyFingerprint
    ) {
        System.out.print("{\"connected\":false,\"status\":\"");
        System.out.print(jsonEscape(status));
        System.out.print("\",\"phase\":\"");
        System.out.print(jsonEscape(phase));
        System.out.print("\",\"key_fingerprint\":\"");
        System.out.print(jsonEscape(keyFingerprint));
        System.out.print("\",\"message\":\"");
        System.out.print(jsonEscape(message == null ? "" : message));
        System.out.println("\"}");
    }

    private static String jsonEscape(String value) {
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            switch (ch) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        builder.append(String.format("\\u%04x", (int) ch));
                    } else {
                        builder.append(ch);
                    }
            }
        }
        return builder.toString();
    }
}
