#!/bin/bash

check_image_freshness() {
    local dockerfile_time
    dockerfile_time=$(stat -c %Y "$SCRIPT_DIR/Dockerfile" 2>/dev/null) || \
    dockerfile_time=$(stat -f %m "$SCRIPT_DIR/Dockerfile" 2>/dev/null) || return 0

    local image_created
    image_created=$(docker inspect "$DOCKER_IMAGE" --format '{{.Created}}' 2>/dev/null) || {
        format_section_break
        echo "⚠ Sandbox image not found."
        if prompt_confirm "Build image now?" true; then
            cmd_build
        fi
        return 0
    }

    local image_time
    image_time=$(date -d "$image_created" +%s 2>/dev/null) || \
    image_time=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${image_created%%.*}" +%s 2>/dev/null) || return 0

    if [ "$dockerfile_time" -gt "$image_time" ]; then
        format_section_break
        echo "⚠ Dockerfile has changed since the image was built."
        if prompt_confirm "Rebuild image now?" true; then
            cmd_build
        fi
    fi
}
