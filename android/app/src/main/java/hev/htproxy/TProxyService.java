package hev.htproxy;

/**
 * Нативный JNI-мост к C/lwIP библиотеке libhev-socks5-tunnel.so (TUN -> SOCKS5 127.0.0.1:20808)
 */
public class TProxyService {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    public native boolean TProxyStartService(String configPath, int fd);

    public native boolean TProxyStopService();

    public native boolean TProxyIsRunning();

    public native long[] TProxyGetStats();
}
