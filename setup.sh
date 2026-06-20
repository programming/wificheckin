#!/usr/bin/env bash
# setup.sh — Provision and deploy AtlasCheckin
# Safe to re-run: most steps are idempotent or skip gracefully.
set -euo pipefail

PROJECT_NAME="atlascheckin"
FALLBACK_NAME="checkinatlas"
DB_NAME="attendance-db"

echo "=== Step 1: Create D1 database ==="
# wrangler d1 create is idempotent-ish — if the name already exists it errors,
# so we check the output. Run it and capture stdout+stderr.
if wrangler d1 create "$DB_NAME" 2>&1 | tee /tmp/d1_create.txt; then
  echo ""
  echo ">>> IMPORTANT: Copy the database_id from the output above and paste it"
  echo ">>> into wrangler.toml, replacing PLACEHOLDER_REPLACE_WITH_YOUR_DATABASE_ID"
  echo ""
  read -rp "Paste the database_id here and press Enter: " DB_ID
  # Replace placeholder in wrangler.toml
  sed -i.bak "s/PLACEHOLDER_REPLACE_WITH_YOUR_DATABASE_ID/$DB_ID/" wrangler.toml
  echo "Updated wrangler.toml with database_id: $DB_ID"
else
  # If already exists, grep existing id from wrangler pages list or ask user
  echo "D1 database may already exist. Check wrangler.toml has the correct database_id."
fi

echo ""
echo "=== Step 2: Apply database migration ==="
wrangler d1 execute "$DB_NAME" --remote --file=./migrations/001_schema.sql || \
  echo "(Migration may already be applied — continuing)"

echo ""
echo "=== Step 3: Create Pages project ==="
if wrangler pages project create "$PROJECT_NAME" --production-branch main 2>&1; then
  echo "Created project: $PROJECT_NAME"
else
  echo "Project '$PROJECT_NAME' may already exist, or name is taken."
  echo "Trying fallback name: $FALLBACK_NAME"
  if wrangler pages project create "$FALLBACK_NAME" --production-branch main 2>&1; then
    PROJECT_NAME="$FALLBACK_NAME"
    echo "Using project name: $PROJECT_NAME"
    # Update wrangler.toml
    sed -i.bak "s/name = \"atlascheckin\"/name = \"$PROJECT_NAME\"/" wrangler.toml
  else
    echo "Both names taken. Assuming project already exists; continuing with: $PROJECT_NAME"
  fi
fi

echo ""
echo "=== Step 4: Set secrets ==="
echo "You will be prompted to enter each secret value."
echo ""
echo "--- Setting ALLOWED_IPS ---"
echo "(Enter comma-separated IPs or CIDR ranges, e.g.: 203.1.2.3,192.168.1.0/24)"
wrangler pages secret put ALLOWED_IPS --project-name "$PROJECT_NAME"

echo ""
echo "--- Setting ADMIN_KEY ---"
echo "(Enter a strong password you will use to log into /admin)"
wrangler pages secret put ADMIN_KEY --project-name "$PROJECT_NAME"

echo ""
echo "=== Step 5: Deploy ==="
wrangler pages deploy ./dist --project-name "$PROJECT_NAME"

echo ""
echo "=== Step 6: Seed example workers ==="

# Generate 3 UUIDs and seed workers via D1 exec
TOKEN1=$(node -e "console.log(crypto.randomUUID())" 2>/dev/null || \
         python3 -c "import uuid; print(uuid.uuid4())")
TOKEN2=$(node -e "console.log(crypto.randomUUID())" 2>/dev/null || \
         python3 -c "import uuid; print(uuid.uuid4())")
TOKEN3=$(node -e "console.log(crypto.randomUUID())" 2>/dev/null || \
         python3 -c "import uuid; print(uuid.uuid4())")

wrangler d1 execute "$DB_NAME" --remote --command \
  "INSERT OR IGNORE INTO workers (first_name, last_name, token) VALUES ('Alice', 'Tan', '$TOKEN1'), ('Bob', 'Lim', '$TOKEN2'), ('Carol', 'Lee', '$TOKEN3');"

echo ""
BASE_URL="https://${PROJECT_NAME}.pages.dev"
echo "=== Step 7: Check-in URLs ==="
echo ""
echo "Alice Tan:  ${BASE_URL}/checkin?token=${TOKEN1}"
echo "Bob Lim:    ${BASE_URL}/checkin?token=${TOKEN2}"
echo "Carol Lee:  ${BASE_URL}/checkin?token=${TOKEN3}"
echo ""
echo "Admin panel: ${BASE_URL}/admin"
echo "IP helper:   ${BASE_URL}/myip"
echo ""
echo "Setup complete!"
