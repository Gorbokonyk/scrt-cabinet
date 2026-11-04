package com.scrt.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;

@SpringBootApplication
public class ScrtApplication {

	public static void main(String[] args) {
        if (!isDockerRunning()) {
            System.err.println("\n[ПОМИЛКА] Docker не запущено! Будь ласка, запустіть Docker Desktop та спробуйте знову.\n");
            System.exit(1);
        }

        SpringApplication.run(ScrtApplication.class, args);
	}

    private static boolean isDockerRunning() {
        try {
            Process process = new ProcessBuilder("docker", "info").start();
            return process.waitFor() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }
}
