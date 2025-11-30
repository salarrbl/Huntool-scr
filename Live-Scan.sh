#!/bin/bash

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <input_hosts_file>"
  exit 1
fi

input="$1"
output="Live-$1"

# Get total lines
total=$(wc -l < "$input")
if [[ $total -eq 0 ]]; then
  echo "Input file is empty."
  exit 1
fi

> "$output"

count=0
start_time=$(date +%s)

while IFS= read -r domain; do
  ((count++))
  [[ -z "$domain" ]] && continue

  # Current time stats
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))
  if [[ $elapsed -eq 0 ]]; then
    speed=0
  else
    speed=$((count / elapsed))
  fi

  # Estimate time remaining (in seconds)
  if [[ $speed -gt 0 ]]; then
    remaining=$(( (total - count) / speed ))
  else
    remaining=0
  fi

  # Format time as MM:SS
  elapsed_str=$(printf "%02d:%02d" $((elapsed/60)) $((elapsed%60)))
  remaining_str=$(printf "%02d:%02d" $((remaining/60)) $((remaining%60)))

  # Status line: [index/total] domain | speed | time | eta
  printf "\r\033[K[%d/%d] %s | %d h/s | Elapsed: %s | ETA: %s" \
    "$count" "$total" "$domain" "$speed" "$elapsed_str" "$remaining_str"

  # Probe the host
  result=$(echo "$domain" | dnsx -duc -silent -retry 10 -r ~/.resolvers 2>/dev/null | \
           httpx -title -sc -duc -cdn -retries 3 -cl -silent 2>/dev/null)

  if [[ -n "$result" ]]; then
    # Print live result on a new line in green
    printf "\r\033[K\033[0;32m✅ [%d/%d] %s\033[0m\n" "$count" "$total" "$result"
    echo "$result" >> "$output"
  fi
done < "$input"

# Final stats
end_time=$(date +%s)
total_elapsed=$((end_time - start_time))
total_elapsed_str=$(printf "%02d:%02d" $((total_elapsed/60)) $((total_elapsed%60)))

printf "\n✅ Scan completed in %s | Avg speed: %d hosts/sec\n" "$total_elapsed_str" $((total / (total_elapsed > 0 ? total_elapsed : 1)))
echo "Live hosts saved to: $output"

