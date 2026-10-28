#!/usr/bin/env bash
# Interactively stores bot secrets in .env (owner-only) next to this script
# and sets up rules.txt from rules.example.txt.
# Leave a prompt empty to keep the current value.
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
ENVF=$DIR/.env
RULES=$DIR/rules.txt
umask 077
touch "$ENVF"

set_kv() {
  local key=$1 value=$2
  grep -v "^${key}=" "$ENVF" > "$ENVF.tmp" || true
  printf '%s=%s\n' "$key" "$value" >> "$ENVF.tmp"
  mv "$ENVF.tmp" "$ENVF"
}

ask() {
  local key=$1 prompt=$2 secret=$3 value
  if [ "$secret" = 1 ]; then read -rsp "$prompt: " value; echo; else read -rp "$prompt: " value; fi
  [ -n "$value" ] && set_kv "$key" "$value"
  return 0
}

ask BOT_TOKEN        "Токен бота от @BotFather" 1
ask CF_ACCOUNT_ID    "Cloudflare Account ID" 0
ask CF_API_TOKEN     "Cloudflare API token (Workers AI)" 1
ask TYPESAFE_API_KEY "TypeSafe (Jev) API key" 1
ask CAS_API_KEY      "Combot API key для CAS (необязательно)" 1
ask ADMIN_IDS        "Ваш Telegram ID (несколько через запятую)" 0
ask GROUP_DESCRIPTION "О чём группа, одной фразой (необязательно)" 0

for kv in DRY_RUN=true BAN_THRESHOLD=0.9 DELETE_THRESHOLD=0.7 TRUST_AFTER=3 JEV_MODEL=jev-latest; do
  grep -q "^${kv%%=*}=" "$ENVF" || echo "$kv" >> "$ENVF"
done
echo "Сохранено в $ENVF:"; cut -d= -f1 "$ENVF" | sed 's/^/  /'

# Rules the bot posts under every channel post. An existing rules.txt is kept as is.
if [ -e "$RULES" ]; then
  echo "$RULES уже есть, не трогаю: правьте его вручную."
else
  read -rp "Куда писать, если бот ошибся (например @my_contact_bot или «администратору канала»): " contact
  rules=$(cat "$DIR/rules.example.txt")
  printf '%s\n' "${rules//\{contact\}/${contact:-администратору канала}}" > "$RULES"
  chmod 644 "$RULES"  # the bot reads it inside the container as a non-root user
  echo "Правила сохранены в $RULES, поправьте текст под свою группу."
fi
