#!/bin/bash

cmd_build() {
    parse_build_args "$@"
    local no_cache="$BUILD_NO_CACHE"
    local build_args=""

    # Check for --without-opencode flag
    if [ "${BUILD_WITHOUT_OPENCODE:-0}" = "1" ]; then
        build_args="--build-arg INCLUDE_OPENCODE=0"
    fi

    echo "Building sandbox image..."
    run_cmd docker compose -f "$SCRIPT_DIR/docker-compose.yml" build $no_cache $build_args
    echo "Building credential isolation proxy image..."
    run_cmd docker build $no_cache -t foundry-api-proxy "$SCRIPT_DIR/api-proxy"
}
