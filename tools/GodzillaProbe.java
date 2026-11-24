import core.imp.Payload;
import core.shell.ShellEntity;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public final class GodzillaProbe {
    private GodzillaProbe() {
    }

    public static void main(String[] args) {
        System.setProperty("java.awt.headless", "true");
        if (args.length < 8) {
            printError("invalid_options", "missing Godzilla probe arguments");
            System.exit(2);
        }
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
            applyHeaders(shell, headersEncoded);

            if (!shell.initShellOpertion()) {
                String detail = shell.lastInitError;
                printError("protocol_error", detail == null ? "Godzilla initialization failed" : detail);
                System.exit(1);
            }
            Payload payload = shell.getPayloadModule();
            if (payload == null) {
                printError("protocol_error", "Godzilla payload module is unavailable");
                System.exit(1);
            }
            String sample = payload.getBasicsInfo();
            boolean alive = payload.isAlive();
            if (sample == null) {
                sample = "";
            }
            System.out.print("{\"connected\":true,\"status\":\"connected\",\"alive\":");
            System.out.print(alive);
            System.out.print(",\"payload\":\"");
            System.out.print(jsonEscape(payloadName));
            System.out.print("\",\"cryptor\":\"");
            System.out.print(jsonEscape(cryptor));
            System.out.print("\",\"sample\":\"");
            System.out.print(jsonEscape(sample));
            System.out.println("\"}");
        } catch (Throwable error) {
            printError("protocol_error", error.getClass().getSimpleName() + ": " + error.getMessage());
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

    private static void printError(String status, String message) {
        System.out.print("{\"connected\":false,\"status\":\"");
        System.out.print(jsonEscape(status));
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
