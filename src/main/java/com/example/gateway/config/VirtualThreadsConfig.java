package com.example.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.core.task.VirtualThreadTaskExecutor;
import org.springframework.core.task.support.TaskExecutorAdapter;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import java.util.concurrent.Executors;
/**
 * Enabling and managing Java 21's Virtual Threads across the Security Gateway:
 * web requests, @Async tasks, and @Scheduled tasks.
 * Configuration is activated by the property 'spring.threads.virtual.enabled=true'.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
@EnableAsync
@EnableScheduling
@ConditionalOnProperty(value = "spring.threads.virtual.enabled", havingValue = "true")
public class VirtualThreadsConfig implements SchedulingConfigurer {
  /**
   Configures the default task executor for all @Async methods in the application.
   This ensures any general-purpose asynchronous task will run on a virtual thread.
   @return An AsyncTaskExecutor backed by a virtual thread per task executor.
   */
  @Bean
  public AsyncTaskExecutor applicationTaskExecutor() {
    log.info("Configuring AsyncTaskExecutor to use Virtual Threads for @Async tasks.");
    return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
  }
  /**
   * Creates a custom TaskScheduler bean that will be used by all @Scheduled methods.
   * This bean is configured to use a backing executor that creates a new virtual thread
   * for each scheduled task invocation. This is the correct way to make @Scheduled
   * tasks run on virtual threads.
   *
   * @return A TaskScheduler configured to use virtual threads.
   */
  @Bean
  @ConditionalOnProperty(value = "spring.threads.virtual.enabled", havingValue = "true")
  public TaskScheduler taskScheduler() {
    log.info("Configuring TaskScheduler to use Virtual Threads for @Scheduled tasks.");
    ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();

    // Set a reasonable pool size. This is the max number of *concurrent* scheduled tasks.
    scheduler.setPoolSize(10);

    // This is the key: Set the actual executor that will run the tasks.
    // We provide a VirtualThreadTaskExecutor, so each task runs in its own virtual thread.
    scheduler.setTaskExecutor(new VirtualThreadTaskExecutor("scheduled-virtual-thread-"));

    // It's good practice to set a thread name prefix for easier debugging.
    scheduler.setThreadNamePrefix("scheduled-task-vt-");

    return scheduler;
  }
}
