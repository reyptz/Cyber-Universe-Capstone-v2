#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stdint.h>
#include <stddef.h>

// Payload execution context
typedef struct {
    uint32_t pid;
    uint32_t target_pid;
    void* base_address;
    size_t payload_size;
    uint8_t encryption_key;
} payload_context_t;

// Payload types
typedef enum {
    PAYLOAD_TYPE_SHELLCODE = 1,
    PAYLOAD_TYPE_DLL_INJECTION = 2,
    PAYLOAD_TYPE_PROCESS_HOLLOWING = 3,
    PAYLOAD_TYPE_REFLECTIVE_LOADER = 4
} payload_type_t;

// Injection techniques
typedef enum {
    INJECTION_TECHNIQUE_CREATE_REMOTE_THREAD = 1,
    INJECTION_TECHNIQUE_QUEUE_USER_APC = 2,
    INJECTION_TECHNIQUE_SET_WINDOWS_HOOK = 3,
    INJECTION_TECHNIQUE_PROCESS_HOLLOWING = 4
} injection_technique_t;

// Obfuscation methods
typedef enum {
    OBFUSCATION_XOR = 1,
    OBFUSCATION_AES = 2,
    OBFUSCATION_POLYMORPHIC = 3,
    OBFUSCATION_METAMORPHIC = 4
} obfuscation_method_t;

// Function declarations
int create_payload_context(payload_context_t* ctx, uint32_t target_pid, payload_type_t type);
int execute_payload_injection(payload_context_t* ctx, const uint8_t* payload, size_t size, injection_technique_t technique);
int apply_obfuscation(uint8_t* data, size_t size, obfuscation_method_t method, uint8_t key);
int validate_payload_integrity(const uint8_t* payload, size_t size, uint32_t expected_hash);
void cleanup_payload_context(payload_context_t* ctx);

// MITRE ATT&CK technique mappings
#define MITRE_T1055_PROCESS_HOLLOWING  "T1055.012"
#define MITRE_T1055_DLL_INJECTION    "T1055.001"
#define MITRE_T1055_REFLECTIVE_LOADER "T1055.001"
#define MITRE_T1566_HOOK_INJECTION   "T1566.002"

#endif // PAYLOAD_H
