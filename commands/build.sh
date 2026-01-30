#!/bin/bash

cmd_build() {
    parse_build_args "$@"
    local no_cache="$BUILD_NO_CACHE"
    echo "Building sandbox image..."
    run_cmd docker compose -f "$SCRIPT_DIR/docker-compose.yml" build $no_cache
    echo "Building credential isolation proxy image..."
    run_cmd docker build $no_cache -t foundry-api-proxy "$SCRIPT_DIR/api-proxy"
}
