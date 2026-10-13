/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.tooling.config;

import com.google.auto.service.AutoService;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporterBuilder;
import io.opentelemetry.exporter.otlp.http.metrics.OtlpHttpMetricExporter;
import io.opentelemetry.exporter.otlp.http.metrics.OtlpHttpMetricExporterBuilder;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporterBuilder;
import io.opentelemetry.exporter.otlp.internal.HttpExporterBuilder;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurationException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Adds support for the {@code http/json} OTLP protocol, which the SDK autoconfigure module does not
 * accept (it only supports {@code grpc} and {@code http/protobuf}).
 *
 * <p>The SDK's HTTP exporters are already able to send JSON payloads, but that option isn't exposed
 * through configuration. When {@code http/json} is configured for a signal, this customizer
 * rewrites the protocol to {@code http/protobuf} so that the SDK creates the regular HTTP exporter
 * (including endpoint, headers, TLS, compression, etc.), and then rebuilds that exporter with JSON
 * encoding enabled.
 *
 * <p>When {@code otel.exporter.otlp.insecure-skip-tls-verify} is {@code true}, the OTLP HTTP
 * exporters (both {@code http/json} and {@code http/protobuf}) are also rebuilt to trust any server
 * certificate. This is meant for networks where a TLS-intercepting proxy re-signs traffic with a
 * certificate the JVM doesn't trust; prefer {@code otel.exporter.otlp.certificate} with the proxy's
 * CA certificate whenever it is available.
 */
@AutoService(AutoConfigurationCustomizerProvider.class)
public class OtlpHttpJsonProtocolCustomizerProvider implements AutoConfigurationCustomizerProvider {

  private static final Logger logger =
      Logger.getLogger(OtlpHttpJsonProtocolCustomizerProvider.class.getName());

  static final String PROTOCOL_HTTP_JSON = "http/json";
  private static final String PROTOCOL_HTTP_PROTOBUF = "http/protobuf";
  static final String INSECURE_SKIP_TLS_VERIFY = "otel.exporter.otlp.insecure-skip-tls-verify";

  private static final String TRACES = "traces";
  private static final String METRICS = "metrics";
  private static final String LOGS = "logs";

  private final Set<String> jsonSignals = ConcurrentHashMap.newKeySet();
  private final AtomicBoolean insecureWarningLogged = new AtomicBoolean();

  @Override
  public void customize(AutoConfigurationCustomizer autoConfigurationCustomizer) {
    autoConfigurationCustomizer
        .addPropertiesCustomizer(this::customizeProperties)
        .addSpanExporterCustomizer(
            (exporter, config) -> {
              if (!(exporter instanceof OtlpHttpSpanExporter)) {
                return exporter;
              }
              boolean json = jsonSignals.contains(TRACES);
              boolean insecure = isInsecure(config);
              if (!json && !insecure) {
                return exporter;
              }
              OtlpHttpSpanExporterBuilder builder = ((OtlpHttpSpanExporter) exporter).toBuilder();
              if (json) {
                enableJson(builder);
              }
              if (insecure) {
                builder.setSslContext(trustAllSslContext(), TrustAllTrustManager.INSTANCE);
              }
              exporter.shutdown();
              return builder.build();
            })
        .addMetricExporterCustomizer(
            (exporter, config) -> {
              if (!(exporter instanceof OtlpHttpMetricExporter)) {
                return exporter;
              }
              boolean json = jsonSignals.contains(METRICS);
              boolean insecure = isInsecure(config);
              if (!json && !insecure) {
                return exporter;
              }
              OtlpHttpMetricExporterBuilder builder =
                  ((OtlpHttpMetricExporter) exporter).toBuilder();
              if (json) {
                enableJson(builder);
              }
              if (insecure) {
                builder.setSslContext(trustAllSslContext(), TrustAllTrustManager.INSTANCE);
              }
              exporter.shutdown();
              return builder.build();
            })
        .addLogRecordExporterCustomizer(
            (exporter, config) -> {
              if (!(exporter instanceof OtlpHttpLogRecordExporter)) {
                return exporter;
              }
              boolean json = jsonSignals.contains(LOGS);
              boolean insecure = isInsecure(config);
              if (!json && !insecure) {
                return exporter;
              }
              OtlpHttpLogRecordExporterBuilder builder =
                  ((OtlpHttpLogRecordExporter) exporter).toBuilder();
              if (json) {
                enableJson(builder);
              }
              if (insecure) {
                builder.setSslContext(trustAllSslContext(), TrustAllTrustManager.INSTANCE);
              }
              exporter.shutdown();
              return builder.build();
            });
  }

  private Map<String, String> customizeProperties(ConfigProperties config) {
    jsonSignals.clear();
    Map<String, String> overrides = new HashMap<>();

    String generalProtocol = config.getString("otel.exporter.otlp.protocol");
    for (String signal : new String[] {TRACES, METRICS, LOGS}) {
      String key = "otel.exporter.otlp." + signal + ".protocol";
      String protocol = config.getString(key);
      if (protocol == null) {
        protocol = generalProtocol;
      }
      if (PROTOCOL_HTTP_JSON.equals(protocol)) {
        jsonSignals.add(signal);
        overrides.put(key, PROTOCOL_HTTP_PROTOBUF);
      }
    }
    if (PROTOCOL_HTTP_JSON.equals(generalProtocol)) {
      overrides.put("otel.exporter.otlp.protocol", PROTOCOL_HTTP_PROTOBUF);
    }
    return overrides;
  }

  private boolean isInsecure(ConfigProperties config) {
    if (!config.getBoolean(INSECURE_SKIP_TLS_VERIFY, false)) {
      return false;
    }
    if (insecureWarningLogged.compareAndSet(false, true)) {
      logger.warning(
          INSECURE_SKIP_TLS_VERIFY
              + " is enabled: OTLP HTTP exporters will not verify the server certificate."
              + " Do not use this outside of trusted networks.");
    }
    return true;
  }

  // the public OTLP HTTP exporter builders don't expose JSON encoding, but the internal
  // HttpExporterBuilder they delegate to does
  private static void enableJson(Object exporterBuilder) {
    try {
      Field field = exporterBuilder.getClass().getDeclaredField("delegate");
      field.setAccessible(true);
      ((HttpExporterBuilder) field.get(exporterBuilder)).exportAsJson();
    } catch (ReflectiveOperationException | RuntimeException e) {
      throw new ConfigurationException(
          "OTLP protocol "
              + PROTOCOL_HTTP_JSON
              + " is not supported by this OpenTelemetry SDK version",
          e);
    }
  }

  private static SSLContext trustAllSslContext() {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, new TrustManager[] {TrustAllTrustManager.INSTANCE}, null);
      return sslContext;
    } catch (GeneralSecurityException e) {
      throw new ConfigurationException(
          "Could not create SSLContext for " + INSECURE_SKIP_TLS_VERIFY, e);
    }
  }

  private static final class TrustAllTrustManager implements X509TrustManager {
    static final TrustAllTrustManager INSTANCE = new TrustAllTrustManager();

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }

  @Override
  public int order() {
    // run AFTER other customizers, so that a http/json protocol set by them is also handled
    return Integer.MAX_VALUE;
  }
}
