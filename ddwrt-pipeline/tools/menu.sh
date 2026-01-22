#!/bin/bash

# This script dynamically reads and displays a nested menu structure from menu-config.json.
# It requires the 'jq' command-line JSON processor to be installed.

MENU_CONFIG="../menu-config.json"

# Function to check for jq
check_jq() {
    if ! command -v jq &> /dev/null
    then
        echo "Error: 'jq' is required for dynamic menu processing." >&2
        echo "Please install it (e.g., 'sudo apt install jq' on Debian/Ubuntu)." >&2
        exit 1
    fi
}

# Global variables to hold the loaded data from a category query
MENU_NAMES=""
MENU_COMMANDS=""
MENU_COUNT=0

load_menu_data() {
    local category_key="$1"

    # jq query to pull names and commands, separated by spaces for easier Bash array conversion
    MENU_NAMES=$(jq -r --arg key "$category_key" '.[$key][].name' "$MENU_CONFIG" | tr '\n' ' ')
    MENU_COMMANDS=$(jq -r --arg key "$category_key" '.[$key][].command' "$MENU_CONFIG" | tr '\n' ' ')

    # Count the number of items loaded
    local COUNT_STRING=$(jq -r --arg key "$category_key" '.[$key] | length' "$MENU_CONFIG")
    MENU_COUNT=${COUNT_STRING:-0}
}

show_submenu_and_execute() {
    local submenu_title="$1"
    local category_key="$2"

    load_menu_data "$category_key"

    if [ $MENU_COUNT -eq 0 ]; then
        echo "No options found in the '$category_key' category in menu-config.json."
        return
    fi

    # Convert space-separated strings to arrays
    local -a NAMES_ARRAY=($MENU_NAMES)
    local -a COMMANDS_ARRAY=($MENU_COMMANDS)

    # Add the navigation option
    NAMES_ARRAY+=("<- Back to Main Menu")

    echo ""
    echo "--- $submenu_title ---"

    select opt in "${NAMES_ARRAY[@]}"
    do
        if [ "$opt" == "<- Back to Main Menu" ]; then
            break # Return to the calling function (top_menu)
        elif [ -n "$opt" ]; then
            local INDEX=$((REPLY - 1))
            local COMMAND=${COMMANDS_ARRAY[INDEX]}

            if [ -n "$COMMAND" ]; then
                echo "Executing: $COMMAND"
                bash -c "$COMMAND"
                # Exit after a concrete action (build, clean, update) is performed
                exit 0
            else
                echo "Invalid option: Command not found for selection index $REPLY."
            fi
        else
            echo "Invalid selection: $REPLY"
        fi
    done
}

build_submenu() {
    show_submenu_and_execute "Firmware Build Targets" "Build"
}

hardware_submenu() {
    show_submenu_and_execute "Hardware Information & Utilities" "Hardware"
}

top_menu() {

    # 1. Load the general utility options from the "Options" category
    load_menu_data "Options"
    local -a GLOBAL_NAMES_ARRAY=($MENU_NAMES)
    local -a GLOBAL_COMMANDS_ARRAY=($MENU_COMMANDS)

    # 2. Define the main categories and combine with global options
    local -a TOP_OPTIONS=(
        "Build Firmware Targets (Submenu)"
        "Hardware Info & Utilities (Submenu)"
    )
    # Append the general utility options
    TOP_OPTIONS+=("${GLOBAL_NAMES_ARRAY[@]}")
    TOP_OPTIONS+=("Exit Menu")

    while true; do
        echo ""
        echo "--- DD-WRT Pipeline Menu (Dynamic) ---"
        echo "Select an action or category:"

        select opt in "${TOP_OPTIONS[@]}"
        do
            case $opt in
                "Build Firmware Targets (Submenu)")
                    build_submenu
                    break # Restart top menu selection after submenu returns
                    ;;
                "Hardware Info & Utilities (Submenu)")
                    hardware_submenu
                    break # Restart top menu selection after submenu returns
                    ;;
                "Exit Menu")
                    echo "Exiting."
                    exit 0
                    ;;
                *)
                    # Handle the direct execution of global options (Options array)
                    local FOUND=false
                    for i in "${!GLOBAL_NAMES_ARRAY[@]}"; do
                        if [[ "${GLOBAL_NAMES_ARRAY[i]}" == "$opt" ]]; then
                            local COMMAND=${GLOBAL_COMMANDS_ARRAY[i]}
                            echo "Executing: $COMMAND"
                            bash -c "$COMMAND"
                            exit 0
                            FOUND=true
                            break
                        fi
                    done

                    if [ "$FOUND" == false ]; then
                        echo "Invalid selection: $REPLY"
                    fi
                    break # Break out of the select loop to redraw menu
                    ;;
            esac
        done
    done
}

main() {
    check_jq
    top_menu
}

main
