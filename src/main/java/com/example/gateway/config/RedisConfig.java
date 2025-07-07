package com.example.gateway.config;


import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.SslOptions;
import io.lettuce.core.cluster.ClusterClientOptions;
import io.lettuce.core.cluster.ClusterTopologyRefreshOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisClusterConfiguration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

/**
 * Redis Configuration with TLS and Key Vault integration
 *
 * Features:
 * - TLS/SSL encryption
 * - Password from Azure Key Vault
 * - Connection pooling for low latency
 * - Support for standalone and cluster modes
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
public class RedisConfig {

  @Autowired
  private AzureKeyVaultClient keyVaultClient;

  @Value("${spring.redis.mode:standalone}")
  private String redisMode;

  @Value("${spring.redis.host:localhost}")
  private String redisHost;

  @Value("${spring.redis.port:6380}")
  private int redisPort;

  @Value("${spring.redis.ssl.enabled:true}")
  private boolean sslEnabled;

  @Value("${spring.redis.cluster.nodes:}")
  private String clusterNodes;

  @Value("${spring.redis.timeout:2000ms}")
  private Duration timeout;

  @Bean
  public RedisConnectionFactory redisConnectionFactory() {
    String redisPassword = keyVaultClient.getSecret("redis-password");

    if ("cluster".equalsIgnoreCase(redisMode) && !clusterNodes.isEmpty()) {
      return createClusterConnectionFactory(redisPassword);
    } else {
      return createStandaloneConnectionFactory(redisPassword);
    }
  }

  @Bean
  public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
    RedisTemplate<String, String> template = new RedisTemplate<>();
    template.setConnectionFactory(connectionFactory);

    StringRedisSerializer serializer = new StringRedisSerializer();
    template.setKeySerializer(serializer);
    template.setValueSerializer(serializer);
    template.setHashKeySerializer(serializer);
    template.setHashValueSerializer(serializer);

    template.afterPropertiesSet();
    return template;
  }

  private RedisConnectionFactory createStandaloneConnectionFactory(String password) {
    RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration();
    redisConfig.setHostName(redisHost);
    redisConfig.setPort(redisPort);
    redisConfig.setPassword(password);

    LettuceClientConfiguration.LettuceClientConfigurationBuilder builder =
        LettuceClientConfiguration.builder()
            .commandTimeout(timeout)
            .shutdownTimeout(Duration.ofSeconds(2));

    if (sslEnabled) {
      builder.useSsl().and().clientOptions(createSecureClientOptions());
    } else {
      builder.clientOptions(createClientOptions());
    }

    return new LettuceConnectionFactory(redisConfig, builder.build());
  }

  private RedisConnectionFactory createClusterConnectionFactory(String password) {
    RedisClusterConfiguration clusterConfig = new RedisClusterConfiguration();

    String[] nodes = clusterNodes.split(",");
    for (String node : nodes) {
      String[] parts = node.trim().split(":");
      clusterConfig.addClusterNode(parts[0], Integer.parseInt(parts[1]));
    }

    clusterConfig.setPassword(password);

    ClusterTopologyRefreshOptions topologyRefreshOptions =
        ClusterTopologyRefreshOptions.builder()
            .enablePeriodicRefresh(Duration.ofMinutes(1))
            .enableAllAdaptiveRefreshTriggers()
            .build();

    ClusterClientOptions clientOptions = ClusterClientOptions.builder()
        .topologyRefreshOptions(topologyRefreshOptions)
        .socketOptions(createSocketOptions())
        .sslOptions(sslEnabled ? createSslOptions() : null)
        .validateClusterNodeMembership(false)
        .build();

    LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
        .clientOptions(clientOptions)
        .commandTimeout(timeout)
        .useSsl(sslEnabled)
        .build();

    return new LettuceConnectionFactory(clusterConfig, clientConfig);
  }

  private ClientOptions createSecureClientOptions() {
    return ClientOptions.builder()
        .socketOptions(createSocketOptions())
        .sslOptions(createSslOptions())
        .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)
        .build();
  }

  private ClientOptions createClientOptions() {
    return ClientOptions.builder()
        .socketOptions(createSocketOptions())
        .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)
        .build();
  }

  private SocketOptions createSocketOptions() {
    return SocketOptions.builder()
        .connectTimeout(timeout)
        .keepAlive(true)
        .tcpNoDelay(true)
        .build();
  }

  private SslOptions createSslOptions() {
    return SslOptions.builder()
        .jdkSslProvider()
        .build();
  }
}
