#!/bin/bash

# This script performs the main DD-WRT build sequence or utility actions.
# Usage: ./build-helper.sh <action> [target]
# Actions: build, info, hardware_info, update_source

# --- Configuration Variables ---
DDWRT_SOURCE_DIR="ddwrt_source"
PATCHES_DIR="parse/patches"
DDWRT_SOURCE="svn://svn.dd-wrt.com/src/trunk"

# Read the action and optional target from the command line arguments
ACTION=${1:-"build"} # Default to 'build' if no action is provided
BUILD_TARGET=${2}    # Target (e.g., broadcom-4700) is the second argument

# --- Utility Functions ---

gather_host_info() {
    echo "--- Host Environment Information (WSL/Linux) ---"
    echo "Kernel/OS Info:"
    uname -a
    echo ""

    echo "CPU Architecture/Cores:"
    # Filter for relevant CPU details
    lscpu | grep -E 'Model name|Architecture|CPU\(s\):|Thread\(s\):|Core\(s\):'
    echo ""

    echo "Memory Status:"
    free -h
    echo ""

    echo "Disk Usage (Root Filesystem):"
    df -h /
    echo "------------------------------------------------"
}

gather_router_hardware() {
    if [ -z "$BUILD_TARGET" ]; then
        echo "Error: Target architecture must be specified for hardware lookup."
        return 1
    fi

    echo "--- Router Hardware Information for Target: $BUILD_TARGET ---"

    # NOTE: In a real scenario, this would query a database or config file
    # For this example, we use a simple case statement to simulate a lookup.
    case "$BUILD_TARGET" in
        "broadcom-4700")
            echo "Architecture: Broadcom BCM4700 Series (MIPS)"
            echo "CPU: MIPS32 @ 200-240MHz"
            echo "RAM: Typically 16MB - 32MB"
            echo "Flash: Typically 4MB"
            echo "Example Devices: Linksys WRT54G (v1-v4), Buffalo WZR-HP-G300NH"
            ;;
        "ath79")
            echo "Architecture: Atheros AR7xxx/AR9xxx (MIPS)"
            echo "CPU: MIPS 74Kc @ 400-720MHz"
            echo "RAM: Typically 64MB - 128MB"
            echo "Flash: Typically 8MB - 16MB"
            echo "Example Devices: TP-Link TL-WR1043ND, Ubiquiti UniFi LR"
            ;;
        *)
            echo "Warning: No specific hardware data found for target '$BUILD_TARGET'."
            echo "This target may require manual configuration lookup."
            ;;
    esac
    echo "------------------------------------------------------"
}

# --- Source Management Functions ---

clone_source() {
    echo "Checking DD-WRT source directory..."
    if [ ! -d "$DDWRT_SOURCE_DIR" ]; then
        echo "Source directory not found. Performing initial clone..."
        # svn checkout "$DDWRT_SOURCE" "$DDWRT_SOURCE_DIR"
        echo "Placeholder: Performing initial SVN checkout into $DDWRT_SOURCE_DIR."
    else
        echo "Source directory exists. Use 'update_source' to fetch latest changes."
    fi
}

update_source() {
    echo "Updating DD-WRT source code..."
    if [ -d "$DDWRT_SOURCE_DIR" ]; then
        echo "Running 'svn update' in $DDWRT_SOURCE_DIR..."
        # cd "$DDWRT_SOURCE_DIR" && svn update && cd -
        echo "Placeholder: SVN update completed."
    else
        echo "Error: Source directory '$DDWRT_SOURCE_DIR' does not exist. Please run a build or clone first."
        return 1
    fi
}

# --- Build Pipeline Functions ---

apply_patches() {
    echo "Applying custom patches from $PATCHES_DIR..."
    if [ -d "$PATCHES_DIR" ]; then
        # cd $DDWRT_SOURCE_DIR
        # find ../"$PATCHES_DIR" -name "*.patch" -exec patch -p1 -i {} \;
        echo "Placeholder: Patch application skipped. Add your patch application logic."
    fi
}

configure_and_build() {
    if [ -z "$BUILD_TARGET" ]; then
        echo "Error: Build target must be specified."
        return 1
    fi

    echo "Configuring and building firmware for target: $BUILD_TARGET..."
    # cd $DDWRT_SOURCE_DIR

    # 1. Apply default config
    # make ${BUILD_TARGET}_config

    # 2. Start the build
    # make -j$(nproc)

    echo "Placeholder: Build process skipped. Add your make commands here."
}

# --- Main Logic ---

main() {
    case "$ACTION" in
        "info")
            gather_host_info
            ;;
        "hardware_info")
            gather_router_hardware
            ;;
        "update_source")
            update_source
            ;;
        "build")
            echo "--- Starting DD-WRT Build for Target: $BUILD_TARGET ---"
            clone_source # Will only clone if source dir is missing
            apply_patches
            configure_and_build
            echo "Build process completed (placeholders executed). Edit build-helper.sh for real action."
            ;;
        *)
            echo "Error: Unknown action '$ACTION'. Use 'build', 'info', 'hardware_info', or 'update_source'."
            exit 1
            ;;
    esac
}

# --- Execution ---
main
