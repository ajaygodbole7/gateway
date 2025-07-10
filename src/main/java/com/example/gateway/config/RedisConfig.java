package com.example.gateway.config;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.properties.ApplicationProperties;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.SslOptions;
import io.lettuce.core.TimeoutOptions;
import io.lettuce.core.api.StatefulConnection;
import io.lettuce.core.cluster.ClusterClientOptions;
import io.lettuce.core.cluster.ClusterTopologyRefreshOptions;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.springframework.boot.actuate.data.redis.RedisHealthIndicator;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisClusterConfiguration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisNode;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

/**
 * Redis configuration with performance optimizations.
 * Supports both standalone and cluster modes with connection pooling.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
@EnableCaching
@RequiredArgsConstructor
public class RedisConfig {

  private final AzureKeyVaultClient keyVaultClient;
  private final ApplicationProperties properties;

  /**
   * Shared client resources for all Redis connections
   */
  @Bean
  public ClientResources lettuceClientResources() {
    return DefaultClientResources.builder()
        .ioThreadPoolSize(Runtime.getRuntime().availableProcessors())
        .computationThreadPoolSize(Runtime.getRuntime().availableProcessors())
        .build();
  }

  /**
   * Connection pool configuration for optimal performance
   */
  @Bean
  public GenericObjectPoolConfig<StatefulConnection<?, ?>> redisPoolConfig() {
    ApplicationProperties.RedisProperties.PoolProperties poolProps = properties.redis().pool();

    GenericObjectPoolConfig<StatefulConnection<?, ?>> config = new GenericObjectPoolConfig<>();
    config.setMaxTotal(poolProps.maxActive());
    config.setMaxIdle(poolProps.maxIdle());
    config.setMinIdle(poolProps.minIdle());
    config.setMaxWaitMillis(poolProps.maxWait().toMillis());

    // Performance optimizations
    config.setTestOnBorrow(false);
    config.setTestWhileIdle(true);
    config.setTimeBetweenEvictionRunsMillis(poolProps.timeBetweenEvictionRuns().toMillis());
    config.setMinEvictableIdleTimeMillis(60000);
    config.setNumTestsPerEvictionRun(3);

    return config;
  }

  /**
   * Redis connection factory with cluster support.
   * Note: poolConfig is injected as a parameter to avoid direct method calls
   */
  @Bean
  public RedisConnectionFactory redisConnectionFactory(
      ClientResources clientResources,
      GenericObjectPoolConfig<StatefulConnection<?, ?>> poolConfig) {

    String redisPassword = keyVaultClient.getSecret("redis-password");
    ApplicationProperties.RedisProperties redisProps = properties.redis();

    if ("cluster".equalsIgnoreCase(redisProps.mode()) &&
        redisProps.cluster() != null &&
        redisProps.cluster().nodes() != null &&
        !redisProps.cluster().nodes().isEmpty()) {
      return createClusterConnectionFactory(redisPassword, clientResources, poolConfig);
    } else {
      return createStandaloneConnectionFactory(redisPassword, clientResources, poolConfig);
    }
  }

  /**
   * Primary Redis template for string operations
   */
  @Bean
  @Primary
  public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
    RedisTemplate<String, String> template = new RedisTemplate<>();
    template.setConnectionFactory(connectionFactory);

    StringRedisSerializer stringSerializer = new StringRedisSerializer();
    template.setKeySerializer(stringSerializer);
    template.setValueSerializer(stringSerializer);
    template.setHashKeySerializer(stringSerializer);
    template.setHashValueSerializer(stringSerializer);

    template.setEnableTransactionSupport(false);
    template.afterPropertiesSet();
    return template;
  }

  /**
   * Specialized string template
   */
  @Bean
  public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory connectionFactory) {
    StringRedisTemplate template = new StringRedisTemplate();
    template.setConnectionFactory(connectionFactory);
    template.afterPropertiesSet();
    return template;
  }

  /**
   * JSON Redis template for complex objects
   */
  @Bean
  public RedisTemplate<String, Object> jsonRedisTemplate(RedisConnectionFactory connectionFactory) {
    RedisTemplate<String, Object> template = new RedisTemplate<>();
    template.setConnectionFactory(connectionFactory);

    Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer =
        new Jackson2JsonRedisSerializer<>(Object.class);

    StringRedisSerializer stringSerializer = new StringRedisSerializer();
    template.setKeySerializer(stringSerializer);
    template.setHashKeySerializer(stringSerializer);
    template.setValueSerializer(jackson2JsonRedisSerializer);
    template.setHashValueSerializer(jackson2JsonRedisSerializer);

    template.afterPropertiesSet();
    return template;
  }

  /**
   * Redis health indicator for monitoring
   */
  @Bean
  public RedisHealthIndicator redisHealthIndicator(RedisConnectionFactory connectionFactory) {
    return new RedisHealthIndicator(connectionFactory);
  }

  private RedisConnectionFactory createStandaloneConnectionFactory(
      String password,
      ClientResources clientResources,
      GenericObjectPoolConfig<StatefulConnection<?, ?>> poolConfig) {

    ApplicationProperties.RedisProperties redisProps = properties.redis();

    RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration();
    redisConfig.setHostName(redisProps.host());
    redisConfig.setPort(redisProps.port());
    redisConfig.setPassword(password);
    redisConfig.setDatabase(0);

    LettuceClientConfiguration.LettuceClientConfigurationBuilder builder =
        LettucePoolingClientConfiguration.builder()
            .poolConfig(poolConfig)  // Use injected poolConfig
            .clientResources(clientResources)
            .commandTimeout(redisProps.timeout())
            .shutdownTimeout(Duration.ofSeconds(2))
            .clientOptions(createEnhancedClientOptions(redisProps));

    if (redisProps.ssl().enabled()) {
      builder.useSsl();
    }

    LettuceConnectionFactory factory = new LettuceConnectionFactory(redisConfig, builder.build());
    factory.setShareNativeConnection(true);
    factory.setValidateConnection(false);

    return factory;
  }

  private RedisConnectionFactory createClusterConnectionFactory(
      String password,
      ClientResources clientResources,
      GenericObjectPoolConfig<StatefulConnection<?, ?>> poolConfig) {

    ApplicationProperties.RedisProperties redisProps = properties.redis();
    ApplicationProperties.RedisProperties.ClusterProperties clusterProps = redisProps.cluster();

    RedisClusterConfiguration clusterConfig = new RedisClusterConfiguration();

    String[] nodes = clusterProps.nodes().split(",");
    for (String node : nodes) {
      String[] parts = node.trim().split(":");
      clusterConfig.addClusterNode(new RedisNode(parts[0], Integer.parseInt(parts[1])));
    }

    clusterConfig.setPassword(password);
    clusterConfig.setMaxRedirects(clusterProps.maxRedirects());

    ClusterTopologyRefreshOptions topologyRefreshOptions =
        ClusterTopologyRefreshOptions.builder()
            .enablePeriodicRefresh(Duration.ofMinutes(1))
            .enableAllAdaptiveRefreshTriggers()
            .dynamicRefreshSources(true)
            .closeStaleConnections(true)
            .build();

    ClusterClientOptions clientOptions = createEnhancedClusterClientOptions(
        topologyRefreshOptions, redisProps);

    LettuceClientConfiguration.LettuceClientConfigurationBuilder builder =
        LettucePoolingClientConfiguration.builder()
            .poolConfig(poolConfig)  // Use injected poolConfig
            .clientResources(clientResources)
            .clientOptions(clientOptions)
            .commandTimeout(redisProps.timeout());

    if (redisProps.ssl().enabled()) {
      builder.useSsl();
    }

    return new LettuceConnectionFactory(clusterConfig, builder.build());
  }

  private ClientOptions createEnhancedClientOptions(ApplicationProperties.RedisProperties redisProps) {
    ClientOptions.Builder builder = ClientOptions.builder()
        .socketOptions(createEnhancedSocketOptions(redisProps.timeout()))
        .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)
        .cancelCommandsOnReconnectFailure(false)
        .publishOnScheduler(true)
        .pingBeforeActivateConnection(true)
        .timeoutOptions(TimeoutOptions.enabled(redisProps.timeout()));

    if (redisProps.ssl().enabled()) {
      builder.sslOptions(createSslOptions());
    }

    return builder.build();
  }

  private ClusterClientOptions createEnhancedClusterClientOptions(
      ClusterTopologyRefreshOptions refreshOptions,
      ApplicationProperties.RedisProperties redisProps) {

    ClusterClientOptions.Builder builder = ClusterClientOptions.builder()
        .topologyRefreshOptions(refreshOptions)
        .socketOptions(createEnhancedSocketOptions(redisProps.timeout()))
        .validateClusterNodeMembership(false)
        .maxRedirects(redisProps.cluster().maxRedirects())
        .publishOnScheduler(true)
        .pingBeforeActivateConnection(true)
        .timeoutOptions(TimeoutOptions.enabled(redisProps.timeout()));

    if (redisProps.ssl().enabled()) {
      builder.sslOptions(createSslOptions());
    }

    return builder.build();
  }

  private SocketOptions createEnhancedSocketOptions(Duration timeout) {
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
