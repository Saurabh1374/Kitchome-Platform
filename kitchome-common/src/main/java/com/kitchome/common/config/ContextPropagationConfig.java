package com.kitchome.common.config;

import io.micrometer.context.ContextSnapshot;
import io.micrometer.observation.ObservationRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskDecorator;

import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import java.util.concurrent.Executor;

/**
 * Configuration to handle context propagation for asynchronous tasks.
 * This ensures that tracing information (Trace ID, Span ID) is preserved
 * when switching threads (e.g., @Async methods).
 */
@Configuration
@ConditionalOnClass({ ObservationRegistry.class, ContextSnapshot.class })
public class ContextPropagationConfig {

    @Bean
    public TaskDecorator tracingTaskDecorator() {
        return runnable -> {
            // Capture the current context from the calling thread
            ContextSnapshot snapshot = ContextSnapshot.captureAll();
            return () -> {
                // Scope into the background thread with the captured context
                try (ContextSnapshot.Scope scope = snapshot.setThreadLocals()) {
                    runnable.run();
                }
            };
        };
    }

    @Bean(name = "taskExecutor")
    public Executor taskExecutor(TaskDecorator tracingTaskDecorator) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(25);
        executor.setThreadNamePrefix("kitchome-async-");
        executor.setTaskDecorator(tracingTaskDecorator);
        executor.initialize();
        return executor;
    }
}
