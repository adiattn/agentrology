#!/usr/bin/env bash

set -e

GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

# check if there is a .env file and load it
if [ -f .env ]; then
  echo -e "${GREEN}[ INFO ]${RESET} Loading environment variables from .env file"
  export $(grep -v '^#' .env | xargs)
fi

# Defaults
IMAGE_NAME="agentrology-env:latest"
LLM_MODE="hf"
MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
TASK_NAME="agentrology-task"
BENCHMARK="agentrology-benchmark"
HF_TOKEN=$HF_TOKEN
API_KEY=$API_KEY
IS_DEV="false"
MAX_STEPS=${MAX_STEPS:-40}
API_BASE_URL=""
REASONING_MODE="true"

print_help() {
  echo "Usage: ./run.sh [options]"
  echo ""
  echo "Run inference for Agentrology tasks and benchmarks."
  echo ""
  echo "Options:"
  echo "  --dev                  Enable dev mode"
  echo "  --ollama               Use Ollama (local)"
  echo "  --max-steps <num>      Maximum steps for agent execution (default: 40)"
  echo "  --hf                   Use HuggingFace (default)"
  echo "  --model <name>         Model name"
  echo "  --task <name>          Task name"
  echo "  --benchmark <name>     Benchmark name"
  echo "  --api-url <url>        Override API base URL"
  echo "  --no-reasoning         Disable reasoning mode"
  echo "  --image <name>         Docker image name"
  echo "  --log-file <path>      Log file path"
  echo "  --temperature <num>    Temperature for the LLM"
  echo "  --max-tokens <num>     Max tokens per response"
  echo "  --interactive          Enable interactive mode"
  echo "  --ws-timeout <num>     WebSocket connection timeout in seconds"
  echo "  --benchmark-dir <path> Directory to store benchmark results"
  echo "  --port <num>           Port to expose the environment ui"
  echo "  --help                 Show this help"
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
  --dev)
    IS_DEV="true"
    shift
    ;;
  --ollama)
    LLM_MODE="ollama"
    shift
    ;;
  --hf)
    LLM_MODE="hf"
    shift
    ;;
  --model)
    MODEL_NAME="$2"
    shift 2
    ;;
  --task)
    TASK_NAME="$2"
    shift 2
    ;;
  --benchmark)
    BENCHMARK="$2"
    shift 2
    ;;
  --max-steps)
    MAX_STEPS="$2"
    shift 2
    ;;
  --api-url)
    API_BASE_URL="$2"
    shift 2
    ;;
  --no-reasoning)
    REASONING_MODE="false"
    shift
    ;;
  --image)
    IMAGE_NAME="$2"
    shift 2
    ;;
  --log-file)
    LOG_FILE_OVERRIDE="$2"
    shift 2
    ;;
  --temperature)
    TEMPERATURE="$2"
    shift 2
    ;;
  --max-tokens)
    MAX_TOKENS="$2"
    shift 2
    ;;
  --interactive)
    INTERACTIVE_MODE="true"
    shift
    ;;
  --ws-timeout)
    WS_CONNECTION_TIMEOUT="$2"
    shift 2
    ;;
  --benchmark-dir)
    BENCHMARK_DIR="$2"
    shift 2
    ;;
  --port)
    EXPOSE_PORT="$2"
    shift 2
    ;;
  --help | -h | --usage | h)
    print_help
    exit 0
    ;;
  *)
    echo -e "${RED}[ ERROR ] Unknown option: $1${RESET}"
    exit 1
    ;;
  esac
done

mkdir -p logs

# Env fallback
IMAGE_NAME="${IMAGE_NAME:-agentrology-env:latest}"
MODEL_NAME="${MODEL_NAME:-Qwen/Qwen2.5-72B-Instruct}"
if [ -n "$LOG_FILE_OVERRIDE" ]; then
  LOG_FILE="$LOG_FILE_OVERRIDE"
else
  LOG_FILE="logs/${BENCHMARK}_${TASK_NAME}_${MODEL_NAME//\//_}_$(date +%Y%m%d_%H%M%S).log"
fi

# API URL resolution
if [ -z "$API_BASE_URL" ]; then
  if [ "$LLM_MODE" = "ollama" ]; then
    API_BASE_URL="http://127.0.0.1:11434/v1"
  else
    API_BASE_URL="https://router.huggingface.co/v1"
  fi
fi

print_header() {
  echo -e "${CYAN}============================================================${RESET}"
  echo -e "${CYAN}              AGENTROLOGY INFERENCE RUNNER                  ${RESET}"
  echo -e "${CYAN}============================================================${RESET}"
}

print_config() {
  echo -e "${BLUE}[ INFO ]${RESET} LLM_MODE        = ${LLM_MODE}"
  echo -e "${BLUE}[ INFO ]${RESET} MODEL_NAME      = ${MODEL_NAME}"
  echo -e "${BLUE}[ INFO ]${RESET} API_BASE_URL    = ${API_BASE_URL}"
  echo -e "${BLUE}[ INFO ]${RESET} TASK_NAME       = ${TASK_NAME}"
  echo -e "${BLUE}[ INFO ]${RESET} BENCHMARK       = ${BENCHMARK}"
  echo -e "${BLUE}[ INFO ]${RESET} MAX_STEPS       = ${MAX_STEPS}"
  echo -e "${BLUE}[ INFO ]${RESET} IS_DEV          = ${IS_DEV}"
  echo -e "${BLUE}[ INFO ]${RESET} LOG_FILE        = ${LOG_FILE}"
  echo -e "${BLUE}[ INFO ]${RESET} REASONING_MODE  = ${REASONING_MODE}"
}

print_header
print_config

echo -e "${CYAN}------------------------------------------------------------${RESET}"

if [ "$IS_DEV" = "true" ]; then
  echo -e "${YELLOW}[ DEBUG ] DEV mode enabled${RESET}"
else
  echo -e "${GREEN}[ MODE  ] Production mode${RESET}"
fi

# LLM handling
if [ "$LLM_MODE" = "hf" ]; then
  echo -e "${GREEN}[ LLM   ] HuggingFace${RESET}"

  if [ -z "$HF_TOKEN" ] && [ -z "$API_KEY" ]; then
    echo -e "${RED}[ ERROR ] Missing API key${RESET}"
    exit 1
  fi

elif [ "$LLM_MODE" = "ollama" ]; then
  HF_TOKEN="ollama:local"
  API_KEY="ollama:local"
  echo -e "${GREEN}[ LLM   ] Ollama${RESET}"

  if ! curl -s "$API_BASE_URL" >/dev/null 2>&1; then
    echo -e "${RED}[ ERROR ] Ollama not reachable${RESET}"
    exit 1
  fi
fi

echo -e "${CYAN}------------------------------------------------------------${RESET}"
echo -e "${GREEN}[ RUN   ] Starting inference...${RESET}"

IS_DEV="$IS_DEV" \
  LLM_MODE="$LLM_MODE" \
  API_BASE_URL="$API_BASE_URL" \
  MODEL_NAME="$MODEL_NAME" \
  AGENTROLOGY_TASK="$TASK_NAME" \
  MAX_STEPS="$MAX_STEPS" \
  BENCHMARK="$BENCHMARK" \
  HF_TOKEN="$HF_TOKEN" \
  API_KEY="$API_KEY" \
  REASONING_MODE="$REASONING_MODE" \
  IMAGE_NAME="${IMAGE_NAME:-}" \
  LOG_FILE="${LOG_FILE:-}" \
  TEMPERATURE="${TEMPERATURE:-}" \
  MAX_TOKENS="${MAX_TOKENS:-}" \
  INTERACTIVE_MODE="${INTERACTIVE_MODE:-}" \
  WS_CONNECTION_TIMEOUT="${WS_CONNECTION_TIMEOUT:-}" \
  BENCHMARK_DIR="${BENCHMARK_DIR:-}" \
  EXPOSE_PORT="${EXPOSE_PORT:-}" \
  uv run inference.py 2>&1 | tee "$LOG_FILE"

STATUS=${PIPESTATUS[0]}

echo -e "${CYAN}------------------------------------------------------------${RESET}"

if [ $STATUS -eq 0 ]; then
  echo -e "${GREEN}[ OK    ] Completed successfully${RESET}"
else
  echo -e "${RED}[ FAIL  ] Exit code $STATUS${RESET}"
fi

echo -e "${CYAN}============================================================${RESET}"
