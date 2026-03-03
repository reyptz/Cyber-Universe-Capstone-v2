#include <stdio.h>
#include <stdint.h>
#include "payload.h"

int main(void) {
    // simple smoke test: polymorphic obfuscation should not crash
    uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
    apply_polymorphic_obfuscation(data, 4, 1);
    printf("smoke test passed\n");
    return 0;
}
