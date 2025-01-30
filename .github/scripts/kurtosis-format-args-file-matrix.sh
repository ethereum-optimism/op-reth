#!/usr/bin/env bash

# 
# 
# This is a log script used mostly in the CI pipeline
# 
# It will print a JSON formatted array of kurtosis args files
# passed in as an input to this script
# 
# Usage:
# 
# ./kurtosis-format-args-file-matrix.sh <ARG_FILE> [...<ARG_FILE>]
# 
#

# This scripts expects an array of args files as its arguments
ARGS_FILES=("$@")

# All the echoes must go to stderr since stdout must be a JSON object
echo "Found ${#ARGS_FILES[@]} matching files: ${ARGS_FILES[@]}" 1>&2;

# Format the results as a JSON array
ARGS_FILES_JSON=$(jq -cn --argjson files "$(printf '%s\n' "${ARGS_FILES[@]}" | jq -R . | jq -s .)" '$files')

# Place the JSON array into a JSON object under "args" key
# 
# This way the output can be directly used as a github action matrix definition
ARGS_FILES_MATRIX=$(jq -cn --argjson array "$ARGS_FILES_JSON" '{args: $array}')

# Print the matrix to stdout
echo "$ARGS_FILES_MATRIX"