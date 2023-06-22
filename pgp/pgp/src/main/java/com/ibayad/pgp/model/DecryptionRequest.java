package com.ibayad.pgp.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor

public class DecryptionRequest {
    private String encryptedFilePath;
    private String key;

    // Getters and setters
}
