#!/bin/bash

# DD-WRT Scaffold Creator for Linux/WSL
# This script replicates the directory structure and initial files
# created by the original PowerShell New-DDWRTScaffold.ps1 script.

ROOT_PATH=$1

# --- PROMPT FOR PATH IF MISSING ---
if [ -z "$ROOT_PATH" ]; then
    echo "--- DD-WRT Scaffold Setup ---"
    read -r -p "Enter the directory name for the scaffold (e.g., ddwrt-pipeline): " ROOT_PATH
    if [ -z "$ROOT_PATH" ]; then
        ROOT_PATH="ddwrt-pipeline"
        echo "No path entered. Defaulting to '$ROOT_PATH'."
    fi
fi
# -----------------------------------
read -r -p "Create DD-WRT pipeline scaffold in '$ROOT_PATH'? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "Creating scaffold..."
else
    echo "Operation cancelled."
    exit 0
fi

echo "Creating directories..."
mkdir -p "$ROOT_PATH/parse/tests"
mkdir -p "$ROOT_PATH/tools"

echo "Creating README.md..."
cat << 'EOF_README' > "$ROOT_PATH/README.md"
# DD-WRT Build Pipeline Scaffold

This project scaffold was created to manage custom DD-WRT firmware builds within a Linux/WSL environment.

## Setup for WSL/Linux

1.  **Dependencies:** Ensure you have the necessary build dependencies installed for DD-WRT compilation (e.g., Git, build-essential, libncurses5-dev, etc.).
2.  **Configuration:** Configure your default build options in `tools/menu-config.json`.
3.  **Interactive Menu:** Run the interactive menu to select your target and action:
    ```bash
    ./tools/menu.sh
    ```
4.  **Build Helper:** The core build logic is located in `build-helper.sh`. You **must** customize this script to:
    * Clone the DD-WRT source repository.
    * Apply any custom patches (located in `parse/`).
    * Run `make menuconfig` (if needed) and `make`.

## Important Note

The necessary shell scripts (`.sh` files) have been made executable.
EOF_README

echo "Creating build-helper.sh..."
cat << 'EOF_HELPER' > "$ROOT_PATH/build-helper.sh"
#!/bin/bash

# This script performs the main DD-WRT build sequence.
# Customize the variables below and the steps in the 'main' function.

# --- Configuration Variables ---
DDWRT_SOURCE_DIR="ddwrt_source"
PATCHES_DIR="parse/patches"
# Read the target from the command line argument if passed from menu.sh
BUILD_TARGET=${1:-"broadcom"}
# --- Functions ---
clone_source() {
    echo "Cloning DD-WRT source..."
    if [ ! -d "$DDWRT_SOURCE_DIR" ]; then
        # *** REPLACE with your actual clone command ***
        # svn checkout svn://svn.dd-wrt.com/src/trunk $DDWRT_SOURCE_DIR
        echo "Placeholder: Source code not cloned. Please add your clone command here."
    else
        echo "Source directory exists. Skipping clone."
    fi
}

apply_patches() {
    echo "Applying custom patches from $PATCHES_DIR..."
    if [ -d "$PATCHES_DIR" ]; then
        # cd $DDWRT_SOURCE_DIR
        # find ../"$PATCHES_DIR" -name "*.patch" -exec patch -p1 -i {} \;
        echo "Placeholder: Patch application skipped. Add your patch application logic."
    fi
}

configure_and_build() {
    echo "Configuring and building firmware for target: $BUILD_TARGET..."
    # cd $DDWRT_SOURCE_DIR
    # 1. Apply default config
    # make ${BUILD_TARGET}_config
    # 2. Start the build
    # make -j$(nproc)
    echo "Placeholder: Build process skipped. Add your make commands here."
}

main() {
    echo "--- Starting DD-WRT Build for Target: $BUILD_TARGET ---"
    clone_source
    apply_patches
    configure_and_build
    echo "Build process completed (placeholders executed). Edit build-helper.sh for real action."
}
# --- Execution ---
main
EOF_HELPER
chmod +x "$ROOT_PATH/build-helper.sh"

echo "Creating tools/menu-config.json..."
cat << 'EOF_JSON' > "$ROOT_PATH/tools/menu-config.json"
{
  "buildOptions": [
    {
      "name": "Target: broadcom-4700",
      "command": "../build-helper.sh broadcom-4700",
      "description": "Build firmware for Broadcom based routers (e.g., WRT54G series)."
    },
    {
      "name": "Target: ath79 (MIPS)",
      "command": "../build-helper.sh ath79",
      "description": "Build firmware for Atheros-based MIPS routers."
    },
    {
      "name": "Clean Build Directory",
      "command": "rm -rf ../ddwrt_source/build/*",
      "description": "Remove temporary build files to force a clean compilation."
    }
  ]
}
EOF_JSON

# 5. Create tools/menu.sh (Interactive Menu for Bash)
echo "Creating tools/menu.sh..."
cat << 'EOF_MENU' > "$ROOT_PATH/tools/menu.sh"
#!/bin/bash

# Simple interactive menu for Linux/WSL.
# Note: Full JSON parsing is complex in pure Bash. This script hardcodes the
# commands from tools/menu-config.json for simplicity.

OPTIONS=(
    "1. Target: broadcom-4700 (Build)"
    "2. Target: ath79 (MIPS) (Build)"
    "3. Clean Build Directory"
    "4. Exit Menu"
)

echo "--- DD-WRT Pipeline Menu ---"
select opt in "${OPTIONS[@]}"
do
    case $opt in
        "1. Target: broadcom-4700 (Build)")
            echo "Starting Broadcom build..."
            ../build-helper.sh broadcom-4700
            break
            ;;
        "2. Target: ath79 (MIPS) (Build)")
            echo "Starting Atheros/MIPS build..."
            ../build-helper.sh ath79
            break
            ;;
        "3. Clean Build Directory")
            echo "Executing clean command (requires ddwrt_source/build directory to exist)..."
            rm -rf ../ddwrt_source/build/*
            break
            ;;
        "4. Exit Menu")
            echo "Exiting."
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done
EOF_MENU
chmod +x "$ROOT_PATH/tools/menu.sh"

echo "----------------------------------------------------"
echo "Scaffold creation complete in '$ROOT_PATH'!"
echo "----------------------------------------------------"
echo "To proceed, run the following commands in your WSL Ubuntu-22.04 terminal:"
echo "1. cd $ROOT_PATH"
echo "2. Review and edit the scripts, especially build-helper.sh."
echo "3. Launch the interactive menu:"
echo "   ./tools/menu.sh"
