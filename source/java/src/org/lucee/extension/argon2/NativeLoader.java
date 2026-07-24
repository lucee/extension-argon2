package org.lucee.extension.argon2;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

public class NativeLoader {

    private static final AtomicBoolean LOADED = new AtomicBoolean(false);

    public static synchronized void ensureLoaded() {
        if (LOADED.get()) return; 

        String os = normalizeOs(System.getProperty("os.name", ""));
        String arch = normalizeArch(System.getProperty("os.arch", ""));
        String libFileName = getLibFileName(os, arch);
        String resourcePath = os + "-" + arch + "/" + libFileName;

        File tempDir = new File(System.getProperty("java.io.tmpdir"), "lucee-argon2-native");
        if (!tempDir.exists()) tempDir.mkdirs();

        File nativeLib = new File(tempDir, libFileName);
        if (nativeLib.exists() && nativeLib.length() > 0) {
            setJnaPath(tempDir);
            LOADED.set(true);
            return;
        }

        // The native libraries are bundled inside the same JAR as this class.
        // getResourceAsStream() finds resources relative to the calling class's classloader.
        InputStream is = NativeLoader.class.getResourceAsStream("/" + resourcePath);
        if (is == null) {
            // Fallback: try classloader explicitly
            is = NativeLoader.class.getClassLoader().getResourceAsStream(resourcePath);
        }
        if (is == null) {
            throw new RuntimeException(
                "Native library not found in extension JAR: " + resourcePath + "\n" +
                "Ensure the argon2-extension .lex file is properly installed in Lucee.");
        }

        try {
            FileOutputStream fos = new FileOutputStream(nativeLib);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    fos.write(buf, 0, n);
                }
            } finally {
                fos.close();
                is.close();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract native Argon2 library to " + nativeLib, e);
        }

        setJnaPath(tempDir);
        LOADED.set(true);
    }

    private static void setJnaPath(File tempDir) {
        String jnaPath = System.getProperty("jna.library.path", "");
        if (jnaPath == null || jnaPath.isEmpty()) {
            System.setProperty("jna.library.path", tempDir.getAbsolutePath());
        } else if (!jnaPath.contains(tempDir.getAbsolutePath())) {
            System.setProperty("jna.library.path", jnaPath + File.pathSeparator + tempDir.getAbsolutePath());
        }
    }

    private static String normalizeOs(String os) {
        os = os.toLowerCase();
        if (os.contains("win")) return "win32";
        if (os.contains("mac") || os.contains("darwin")) return "darwin";
        if (os.contains("linux")) return "linux";
        if (os.contains("sunos") || os.contains("solaris")) return "sunos";
        return os;
    }

    private static String normalizeArch(String arch) {
        arch = arch.toLowerCase();
        if (arch.equals("amd64") || arch.equals("x86_64")) return "x86-64";
        if (arch.equals("x86") || arch.equals("i386") || arch.equals("i486") || arch.equals("i586") || arch.equals("i686")) return "x86";
        if (arch.equals("aarch64") || arch.equals("arm64")) return "aarch64";
        if (arch.startsWith("arm")) return "arm";
        return arch;
    }

    private static String getLibFileName(String os, String arch) {
        if ("win32".equals(os)) return "argon2.dll";
        if ("darwin".equals(os)) return "libargon2.dylib";
        return "libargon2.so";
    }
}
