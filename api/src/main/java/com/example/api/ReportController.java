package com.example.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.Map;

@RestController
@RequestMapping("/reports")
public class ReportController {

    @GetMapping
    @PreAuthorize("hasRole('prothetic_user')")
    public ResponseEntity<?> getReport() {
        // Фейковые данные
        return ResponseEntity.ok(Map.of(
                "user", "prothetic1",
                "data", "Some usage data for prosthetic device",
                "timestamp", System.currentTimeMillis()
        ));
    }
}
