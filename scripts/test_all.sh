source "$(pwd)/.env"
WORKING_MODELS=()

while read -r model; do
  echo "[+] Trying model: $model"

  MODEL_RESPONSE=$(curl -s https://openrouter.ai/api/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "$(jq -n \
      --arg model "$model" \
      '{
        model: $model,
        messages: [
          {role: "user", content: "Hi, how are you?"}
        ],
        reasoning: { enabled: true }
      }')")

  # check if error exists
  if echo "$MODEL_RESPONSE" | jq -e '.error' >/dev/null; then
    echo "[-] [ERROR] $(echo "$MODEL_RESPONSE" | jq -r '.error.message')"
    echo "--------------------------------------------------"
    continue
  fi

  content=$(echo "$MODEL_RESPONSE" | jq -r '.choices[0].message.content // empty')
  reasoning=$(echo "$MODEL_RESPONSE" | jq -r '.choices[0].message.reasoning // empty')

  if [ -z "$content" ]; then
    echo "[-] Empty response"
    echo "--------------------------------------------------"
    continue
  fi

  echo "[+] Model $model is working!"
  echo "[+] Content: ${content:0:50}"
  echo "[+] Reasoning: ${reasoning:0:50}"

  echo "--------------------------------------------------"
  WORKING_MODELS+=("$model")

done < <(
  curl -s 'https://openrouter.ai/api/frontend/models' | jq -r '.data[] | select(.endpoint.is_free == true) | .slug'
)

echo "[+] Working models:"
for model in "${WORKING_MODELS[@]}"; do
  echo "$model"
done


# google/gemma-4-26b-a4b-it
# google/gemma-4-31b-it
# nvidia/nemotron-3-super-120b-a12b
# minimax/minimax-m2.5
# nvidia/nemotron-3-nano-30b-a3b
# nvidia/nemotron-nano-12b-v2-vl
# qwen/qwen3-next-80b-a3b-instruct
# nvidia/nemotron-nano-9b-v2
# openai/gpt-oss-120b
# openai/gpt-oss-20b
# z-ai/glm-4.5-air
# qwen/qwen3-coder
# google/gemma-3n-e4b-it
# google/gemma-3-4b-it
# google/gemma-3-12b-it
# google/gemma-3-27b-it
# meta-llama/llama-3.3-70b-instruct
# meta-llama/llama-3.2-3b-instruct
# nousresearch/hermes-3-llama-3.1-405b
