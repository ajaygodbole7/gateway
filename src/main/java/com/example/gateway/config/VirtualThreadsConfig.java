package com.example.gateway.config;

import java.util.concurrent.Executors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.core.task.support.TaskExecutorAdapter;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

/**
 * Enabling and managing Java 21's Virtual Threads across the Security Gateway: web requests, @Async
 * tasks, and @Scheduled tasks. Configuration is activated by the property
 * 'spring.threads.virtual.enabled=true'.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
@EnableAsync
@EnableScheduling
@ConditionalOnProperty(value = "spring.threads.virtual.enabled", havingValue = "true")
public class VirtualThreadsConfig implements SchedulingConfigurer {

    /**
     * Configure the application's task scheduler to ensure that all
     *
     * @Scheduled tasks (like M2M token refresh) run on virtual threads. It uses a standard Java 21
     * virtual thread factory.
     */
    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        log.info("Configuring Spring's Task Scheduler to use Virtual Threads for @Scheduled tasks.");
        taskRegistrar.setScheduler(Executors.newSingleThreadScheduledExecutor(
                Thread.ofVirtual().name("scheduled-task-vt-", 0).factory()));
    }

    /**
     * Configure the default task executor for all @Async methods in the application. Ensures any
     * general-purpose asynchronous task will also run on a virtual thread.
     */
    @Bean
    public AsyncTaskExecutor applicationTaskExecutor() {
        log.info("Configuring AsyncTaskExecutor to use Virtual Threads for @Async tasks.");
        return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
    }
}
