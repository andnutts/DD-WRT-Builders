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
