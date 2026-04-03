#!/usr/local/bin/ksh
# Copyright (c) 2026 Manuel Kuklinski
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Import password-store entries into HashiCorp Vault (KV v2)
# Usage: ./import.ksh <folder> (e.g. www, local, creds)

if [ -z "$1" ]; then
  echo "Usage: $0 <folder> (e.g. www, local, creds)"
  exit 1
fi

FOLDER="$1"
STORE="$HOME/.password-store/$FOLDER"
export GPG_TTY=$(tty)
TMPBLOCKS=$(mktemp /tmp/vault_blocks.XXXXXX)
TMPARGS=$(mktemp /tmp/vault_import.XXXXXX)
TMPSKIP=$(mktemp /tmp/vault_skip.XXXXXX)
TMPUNKNOWN=$(mktemp /tmp/vault_unknown.XXXXXX)

if [ ! -d "$STORE" ]; then
  echo "Error: $STORE does not exist"
  exit 1
fi

find "$STORE" -type f | while read f; do
  rel="${f#$STORE/}"
  entrykey="${rel%.gpg}"
  entrykey="${entrykey%.txt}"

  filetype=$(file -b "$f")
  case "$filetype" in
    *GPG*|*PGP*)
      content=$(gpg --quiet --yes --batch --default-recipient-self --decrypt "$f" 2>/dev/null)
      ;;
    *text*|*ASCII*)
      content=$(cat "$f")
      ;;
    *)
      printf 'UNKNOWN FILE TYPE: %s (%s)\n' "$f" "$filetype" >> "$TMPSKIP"
      continue
      ;;
  esac

  if [ -z "$content" ]; then
    printf 'EMPTY: %s\n' "$f" >> "$TMPSKIP"
    continue
  fi

  > "$TMPARGS"
  > "$TMPUNKNOWN"
  > "$TMPBLOCKS"

  # Split content into blocks separated by empty lines
  block=""
  while IFS= read -r line; do
    if [ -z "$line" ]; then
      if [ -n "$block" ]; then
        printf '%s\n---BLOCK---\n' "$block" >> "$TMPBLOCKS"
        block=""
      fi
    else
      block="${block:+$block
}$line"
    fi
  done <<< "$content"
  [ -n "$block" ] && printf '%s\n---BLOCK---\n' "$block" >> "$TMPBLOCKS"

  # Classify and process blocks
  pw_i=1
  login_i=1
  current_block=""

  while IFS= read -r line; do
    if [ "$line" = "---BLOCK---" ]; then
      [ -z "$current_block" ] && continue

      # First line = password candidate
      bpw=$(printf '%s' "$current_block" | sed -n '1p')
      rest=$(printf '%s' "$current_block" | tail -n +2)

      # Check if block contains known fields
      has_known=$(printf '%s' "$rest" | grep -cE '^[A-Za-z][A-Za-z0-9_]*:')

      if [ -z "$rest" ] || [ "$has_known" -eq 0 ]; then
        # No known fields → custom
        while IFS= read -r l; do
          [ -n "$l" ] && printf '%s\n' "$l" >> "$TMPUNKNOWN"
        done <<EOF
$current_block
EOF
      else
        # Block with known fields → password + fields
        if [ $pw_i -eq 1 ]; then
          printf 'password=%s\n' "$bpw" >> "$TMPARGS"
        else
          printf 'password%d=%s\n' "$pw_i" "$bpw" >> "$TMPARGS"
        fi
        pw_i=$((pw_i+1))

        while IFS= read -r line2; do
          case "$line2" in
            [Ll]ogin:*)
              value=$(printf '%s' "$line2" | sed 's/^[^:]*: *//')
              if [ $login_i -eq 1 ]; then
                printf 'login=%s\n' "$value" >> "$TMPARGS"
              else
                printf 'login%d=%s\n' "$login_i" "$value" >> "$TMPARGS"
              fi
              login_i=$((login_i+1))
              ;;
            [A-Za-z]*:*)
              fkey=$(printf '%s' "$line2" | sed 's/:.*//' | tr '[:upper:]' '[:lower:]' | tr ' ' '_')
              value=$(printf '%s' "$line2" | sed 's/^[^:]*: *//')
              printf '%s=%s\n' "$fkey" "$value" >> "$TMPARGS"
              ;;
            *)
              [ -z "$line2" ] && continue
              printf '%s\n' "$line2" >> "$TMPUNKNOWN"
              ;;
          esac
        done <<EOF
$rest
EOF
      fi

      current_block=""
    else
      current_block="${current_block:+$current_block
}$line"
    fi
  done < "$TMPBLOCKS"

  if [ -s "$TMPUNKNOWN" ]; then
    printf '%s:\n' "$f" >> "$TMPSKIP"
    cat "$TMPUNKNOWN" >> "$TMPSKIP"
    printf '(imported as custom)\n\n' >> "$TMPSKIP"
  fi

  # Build custom as JSON string with real newlines
  if [ -s "$TMPUNKNOWN" ]; then
    custom_json=$(jq -Rs '.' < "$TMPUNKNOWN")
  else
    custom_json=""
  fi

  # Build JSON from key=value lines
  json=$(jq -Rn '
    [inputs | select(contains("=")) |
      . as $line | ($line | index("=")) as $i |
      {($line[:$i]): ($line[$i+1:])}
    ] | add
  ' < "$TMPARGS")

  # Add custom if present
  if [ -n "$custom_json" ]; then
    json=$(printf '%s' "$json" | jq --argjson r "$custom_json" '. + {custom: $r}')
  fi

  echo "Importing: secrets/$FOLDER/$entrykey"
  printf '%s' "$json" | vault kv put "secrets/$FOLDER/$entrykey" -
done

if [ -s "$TMPSKIP" ]; then
  echo ""
  echo "=== NOT IMPORTED ==="
  cat "$TMPSKIP"
fi

rm -f "$TMPARGS" "$TMPSKIP" "$TMPUNKNOWN" "$TMPBLOCKS"
