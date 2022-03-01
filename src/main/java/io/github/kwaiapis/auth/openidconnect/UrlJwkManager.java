package io.github.kwaiapis.auth.openidconnect;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.common.base.Stopwatch;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * @author yaolei03
 * @since 2021-12-01
 */
public class UrlJwkManager {

    private static final Logger LOG = LoggerFactory.getLogger(UrlJwkManager.class);

    private static final long ONE_HOUR_MILLIS = 3600 * 1000;

    private static final long REFRESH_SKEW_MILLIS = 24 * 3600 * 1000;

    private static final AtomicInteger COUNT = new AtomicInteger(0);

    private static final String DEFAULT_PUBLIC_CERTS_ENCODED_URL = "https://app.kwai.com/openapi/certs";

    private final URL url;

    private final Proxy proxy;

    private final Map<String, String> headers;

    private final Integer connectTimeout;

    private final Integer readTimeout;

    private final ObjectReader reader;

    private final Lock lock = new ReentrantLock();

    private Map<String, RSAKey> publicKeyMap;

    private long expirationTimeMilliseconds;

    public UrlJwkManager() throws MalformedURLException {
        this(new URL(DEFAULT_PUBLIC_CERTS_ENCODED_URL), 100, 500, null, null);
    }

    public UrlJwkManager(String url) throws MalformedURLException {
        this(new URL(url), 100, 500, null, null);
    }

    public UrlJwkManager(URL url, Integer connectTimeout, Integer readTimeout, Proxy proxy,
            Map<String, String> headers) {
        this.url = url;
        this.proxy = proxy;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.headers = (headers == null) ?
                       Collections.singletonMap("Accept", "application/json") : headers;
        this.reader = new ObjectMapper().readerFor(Map.class);

        refresh();
        Thread t = new Thread(() -> {
            while (true) {
                if (Thread.interrupted()) {
                    break;
                }
                try {
                    Thread.sleep(ONE_HOUR_MILLIS);
                    refresh();
                } catch (Throwable e) {
                    LOG.error("refresh jwk fail.", e);
                }
            }
        });
        t.setDaemon(true);
        t.setName("task-refresh-jwk-" + COUNT.getAndIncrement());
        t.start();
        LOG.info("create url jwk manager {} success.", url);
    }

    public final RSAKey getPublicKey(String kid) {
        if (publicKeyMap == null || System.currentTimeMillis() > expirationTimeMilliseconds) {
            // should never happen
            refresh();
        }
        return publicKeyMap.get(kid);
    }


    /**
     * Forces a refresh of the public certificates downloaded from {@link #url}.
     *
     * @return {@link UrlJwkManager}
     */
    public void refresh() {
        lock.lock();
        try {
            loadAll();
        } finally {
            lock.unlock();
        }
    }

    private void loadAll() {
        Stopwatch stopwatch = Stopwatch.createStarted();
        Map<String, RSAKey> map = new HashMap<>();
        final List<Map<String, Object>> keys = (List<Map<String, Object>>) getJwks().get("keys");

        if (keys == null || keys.isEmpty()) {
            throw new RuntimeException("No keys found in " + url.toString());
        }

        try {
            for (Map<String, Object> values : keys) {
                RSAKey key = RSAKey.parse(values);
                map.put(key.getKeyID(), key);
            }
        } catch (ParseException e) {
            throw new RuntimeException("Failed to parse jwk from json", e);
        }
        publicKeyMap = Collections.unmodifiableMap(map);
        expirationTimeMilliseconds = System.currentTimeMillis() + REFRESH_SKEW_MILLIS;
        LOG.info("jwk manager load {} public keys success. {}", url, stopwatch.elapsed(TimeUnit.MILLISECONDS));
    }

    private Map<String, Object> getJwks() {
        try {
            final URLConnection c = (proxy == null) ? this.url.openConnection() : this.url.openConnection(proxy);
            if (connectTimeout != null) {
                c.setConnectTimeout(connectTimeout);
            }
            if (readTimeout != null) {
                c.setReadTimeout(readTimeout);
            }

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                c.setRequestProperty(entry.getKey(), entry.getValue());
            }

            try (InputStream inputStream = c.getInputStream()) {
                return reader.readValue(inputStream);
            }
        } catch (IOException e) {
            throw new RuntimeException("Cannot obtain jwks from url " + url, e);
        }
    }
}
