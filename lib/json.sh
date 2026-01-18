#!/bin/bash

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//"/\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    echo "$s"
}

json_array_from_lines() {
    local first=true
    echo "["
    while IFS= read -r line; do
        if [ -z "$line" ]; then
            continue
        fi
        if [ "$first" = true ]; then
            first=false
            echo "  $line"
        else
            echo "  ,$line"
        fi
    done
    echo "]"
}
