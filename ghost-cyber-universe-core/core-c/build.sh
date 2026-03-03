#!/bin/bash
# Genjutsu Engine - Build Script

set -e  # Exit on error

echo "=========================================="
echo "  Genjutsu Engine Build Script"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for LLVM
echo -e "${YELLOW}Checking LLVM installation...${NC}"
if ! command -v llvm-config &> /dev/null; then
    echo -e "${RED}Error: LLVM not found. Please install LLVM 17.${NC}"
    exit 1
fi

LLVM_VERSION=$(llvm-config --version | cut -d. -f1)
echo -e "${GREEN}Found LLVM version: $LLVM_VERSION${NC}"

if [ "$LLVM_VERSION" -lt 17 ]; then
    echo -e "${YELLOW}Warning: LLVM 17+ recommended. Found: $LLVM_VERSION${NC}"
fi

# Create build directory
echo ""
echo -e "${YELLOW}Creating build directory...${NC}"
cd llvm-pass
mkdir -p build
cd build

# Configure with CMake
echo ""
echo -e "${YELLOW}Configuring with CMake...${NC}"
cmake ..

# Build
echo ""
echo -e "${YELLOW}Building PolymorphicPass...${NC}"
START_TIME=$(date +%s)

make -j$(nproc)

END_TIME=$(date +%s)
BUILD_TIME=$((END_TIME - START_TIME))

echo ""
echo -e "${GREEN}✓ Build completed successfully!${NC}"
echo -e "${GREEN}✓ Build time: ${BUILD_TIME} seconds${NC}"

# Check performance target
if [ $BUILD_TIME -lt 180 ]; then
    echo -e "${GREEN}✓ Performance target met: < 180 seconds${NC}"
else
    echo -e "${RED}✗ Performance target exceeded: ${BUILD_TIME}s > 180s${NC}"
fi

# List output
echo ""
echo -e "${YELLOW}Output files:${NC}"
ls -lh lib/PolymorphicPass.so

echo ""
echo -e "${GREEN}=========================================="
echo "  Build Complete!"
echo "==========================================${NC}"
echo ""
echo "Usage example:"
echo "  clang -Xclang -load -Xclang ./lib/PolymorphicPass.so \\"
echo "        -c payload.c -o payload.o"
