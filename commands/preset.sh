#!/bin/bash

cmd_preset() {
    local action="${1:-list}"
    shift 2>/dev/null || true

    case "$action" in
        list)
            echo "Saved presets:"
            echo ""
            list_cast_presets
            ;;
        show)
            local preset_name="$1"
            if [ -z "$preset_name" ]; then
                echo "Usage: cast preset show <name>"
                exit 1
            fi
            show_cast_preset "$preset_name"
            ;;
        delete|rm|remove)
            local preset_name="$1"
            if [ -z "$preset_name" ]; then
                echo "Usage: cast preset delete <name>"
                exit 1
            fi
            delete_cast_preset "$preset_name"
            ;;
        help|--help|-h)
            echo "Preset management for cast new"
            echo ""
            echo "Usage: cast preset <command> [args]"
            echo ""
            echo "Commands:"
            echo "  list              List all saved presets"
            echo "  show <name>       Show preset details"
            echo "  delete <name>     Delete a preset"
            echo ""
            echo "To create a preset, use --save-as with cast new:"
            echo "  cast new owner/repo --wd packages/app --save-as mypreset"
            echo ""
            echo "To use a preset:"
            echo "  cast new --preset mypreset"
            ;;
        *)
            echo "Unknown preset command: $action"
            echo "Run 'cast preset help' for usage."
            exit 1
            ;;
    esac
}
