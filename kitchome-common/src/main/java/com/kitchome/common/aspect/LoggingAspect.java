package com.kitchome.common.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;
import org.springframework.util.StopWatch;

@Slf4j
@Aspect
@Component
public class LoggingAspect {

    /**
     * Pointcut that matches all Spring Beans in the service and controller layers.
     */
    @Pointcut("within(@org.springframework.web.bind.annotation.RestController *) || within(@org.springframework.stereotype.Service *)")
    public void springBeanPointcut() {
    }

    /**
     * Advice that logs when a method is entered and exited.
     */
    @Around("springBeanPointcut()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getSignature().getDeclaringTypeName();

        log.debug("Entering: {}.{} with arguments = {}", className, methodName, joinPoint.getArgs());

        StopWatch stopWatch = new StopWatch();
        stopWatch.start();

        try {
            Object result = joinPoint.proceed();
            stopWatch.stop();
            log.debug("Exiting: {}.{} in {} ms with result = {}", className, methodName, stopWatch.getTotalTimeMillis(),
                    result);
            return result;
        } catch (IllegalArgumentException e) {
            log.error("Illegal argument: {} in {}.{}()", joinPoint.getArgs(), className, methodName);
            throw e;
        } catch (Throwable e) {
            log.error("Exception in {}.{}() with cause = {}", className, methodName,
                    e.getCause() != null ? e.getCause() : "NULL");
            throw e;
        }
    }
}
