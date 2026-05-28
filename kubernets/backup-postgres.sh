#!/bin/bash
# PostgreSQL Backup Script for Kubernetes
# Usage: ./backup-postgres.sh [namespace] [backup-dir]

set -e

NAMESPACE="${1:-default}"
BACKUP_DIR="${2:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}PostgreSQL Backup Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Namespace: ${YELLOW}$NAMESPACE${NC}"
echo -e "Backup Directory: ${YELLOW}$BACKUP_DIR${NC}"
echo ""

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Find PostgreSQL Pod
echo -e "${GREEN}Finding PostgreSQL Pod...${NC}"
POD_NAME=$(kubectl get pods -n "$NAMESPACE" -l app=postgresql -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || \
           kubectl get pods -n "$NAMESPACE" | grep -i postgres | head -1 | awk '{print $1}')

if [ -z "$POD_NAME" ]; then
    echo -e "${RED}Error: PostgreSQL Pod not found in namespace $NAMESPACE${NC}"
    echo -e "${YELLOW}Available pods:${NC}"
    kubectl get pods -n "$NAMESPACE"
    exit 1
fi

echo -e "Found Pod: ${GREEN}$POD_NAME${NC}"

# Get database name from environment or use default
DB_NAME="${POSTGRES_DB:-argus}"

# Get PostgreSQL user
PG_USER="${POSTGRES_USER:-postgres}"

echo -e "Database: ${GREEN}$DB_NAME${NC}"
echo -e "User: ${GREEN}$PG_USER${NC}"
echo ""

# Function to backup single database
backup_database() {
    local db_name=$1
    local backup_file="$BACKUP_DIR/${db_name}_${TIMESTAMP}.sql"
    local compressed_file="${backup_file}.gz"
    
    echo -e "${GREEN}Backing up database: $db_name...${NC}"
    
    # Create backup
    if kubectl exec -n "$NAMESPACE" "$POD_NAME" -- pg_dump -U "$PG_USER" "$db_name" > "$backup_file" 2>/dev/null; then
        # Compress backup
        gzip "$backup_file"
        echo -e "  ${GREEN}✓${NC} Backup saved: $compressed_file"
        echo -e "  ${GREEN}✓${NC} Size: $(du -h "$compressed_file" | cut -f1)"
        return 0
    else
        echo -e "  ${RED}✗${NC} Backup failed for database: $db_name"
        return 1
    fi
}

# Function to backup all databases
backup_all() {
    local backup_file="$BACKUP_DIR/postgres_all_${TIMESTAMP}.sql"
    local compressed_file="${backup_file}.gz"
    
    echo -e "${GREEN}Backing up all databases...${NC}"
    
    if kubectl exec -n "$NAMESPACE" "$POD_NAME" -- pg_dumpall -U "$PG_USER" > "$backup_file" 2>/dev/null; then
        gzip "$backup_file"
        echo -e "  ${GREEN}✓${NC} Backup saved: $compressed_file"
        echo -e "  ${GREEN}✓${NC} Size: $(du -h "$compressed_file" | cut -f1)"
        return 0
    else
        echo -e "  ${RED}✗${NC} Backup failed"
        return 1
    fi
}

# Main backup logic
if [ "$BACKUP_MODE" == "all" ]; then
    backup_all
else
    # Try to backup specific database
    if ! backup_database "$DB_NAME"; then
        echo -e "${YELLOW}Single database backup failed, trying to backup all databases...${NC}"
        backup_all
    fi
fi

# Create backup manifest
cat > "$BACKUP_DIR/backup_manifest_${TIMESTAMP}.txt" <<EOF
PostgreSQL Backup Manifest
==========================
Timestamp: $(date)
Namespace: $NAMESPACE
Pod: $POD_NAME
Database: $DB_NAME
User: $PG_USER
Backup Directory: $BACKUP_DIR

Files:
$(ls -lh "$BACKUP_DIR"/*${TIMESTAMP}* 2>/dev/null | awk '{print $9, "(" $5 ")"}')

EOF

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Backup Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Backup files:"
ls -lh "$BACKUP_DIR"/*${TIMESTAMP}* 2>/dev/null | awk '{print "  " $9, "(" $5 ")"}'
echo ""
echo -e "${GREEN}✓ Backup completed!${NC}"
echo ""
echo -e "${YELLOW}To restore, use:${NC}"
echo -e "  kubectl exec -i -n $NAMESPACE $POD_NAME -- psql -U $PG_USER -d $DB_NAME < <(gunzip -c $BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz)"
