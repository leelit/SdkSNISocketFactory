import android.text.TextUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

/**
 * 满足底层判断连接复用条件：equal(this.hostnameVerifier, that.hostnameVerifier)
 */
public class SDKHostnameVerifier implements HostnameVerifier{

    public String bizHost;

    public SDKHostnameVerifier(String bizHost) {
        this.bizHost = bizHost;
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        return HttpsURLConnection.getDefaultHostnameVerifier().verify(bizHost, session);
    }

    @Override
    public boolean equals(Object o) {
        if (TextUtils.isEmpty(bizHost) || !(o instanceof SDKHostnameVerifier)) {
            return false;
        }
        String thatHost = ((SDKHostnameVerifier) o).bizHost;
        if (TextUtils.isEmpty(thatHost)) {
            return false;
        }
        return bizHost.equals(thatHost);
    }
}
