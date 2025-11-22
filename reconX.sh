#!/bin/bash

# ==============================
# 🔎 Recon
# ==============================

# Vérifier qu'un domaine est fourni
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1

# Configuration des checkpoints
save_checkpoint() {
    local stage="$1"
    mkdir -p checkpoints
    echo "$stage" > "checkpoints/last_stage.txt"
    echo "[✓] Checkpoint saved: $stage"
}

# Vérifier si reprise depuis checkpoint
if [[ -f "checkpoints/last_stage.txt" ]]; then
    LAST_STAGE=$(cat checkpoints/last_stage.txt)
    echo "[↻] Resuming from checkpoint: $LAST_STAGE"
fi

# Prompt for folder name with full path
read -p "Full Folder Path: " folder_path
mkdir -p "$folder_path"
cd "$folder_path" || exit 1

# Organisation des dossiers
mkdir -p {nuclei_results,gf_patterns,sensitive_files,special_scans,web_screenshots,dmarc_check,checkpoints,cloud_buckets,wayback_data,github_recon}

# ==============================
# 🔍 DMARC CHECK
# ==============================
if [[ ! -f "checkpoints/dmarc_done" ]] || [[ "$LAST_STAGE" == "start" ]]; then
    echo "[+]------ DMARC Check ------[+]"
    echo "[+] Checking DMARC record for $domain..."
    dig TXT "_dmarc.$domain" +short > dmarc_check/dmarc_result.txt 2>&1

    if [ -s "dmarc_check/dmarc_result.txt" ] && grep -q "v=DMARC1" dmarc_check/dmarc_result.txt; then
        echo "[✅] DMARC record found and configured"
        grep "v=DMARC1" dmarc_check/dmarc_result.txt
    else
        echo "[❌] No DMARC record found or misconfigured"
    fi
    
    # Additional DNS reconnaissance
    echo "[+] Performing additional DNS reconnaissance..."
    {
        echo "=== NS RECORDS ==="
        dig NS "$domain" +short
        echo ""
        echo "=== MX RECORDS ==="  
        dig MX "$domain" +short
        echo ""
        echo "=== TXT RECORDS ==="
        dig TXT "$domain" +short
        echo ""
        echo "=== A RECORDS ==="
        dig A "$domain" +short
    } > dmarc_check/dns_recon.txt
    
    touch checkpoints/dmarc_done
    save_checkpoint "dmarc"
fi

# ==============================
# 🔍 DNS ZONE TRANSFER SCAN
# ==============================
if [[ ! -f "checkpoints/zone_transfer_done" ]] || [[ "$LAST_STAGE" == "dmarc" ]]; then
    echo "[+]------ DNS Zone Transfer Scan ------[+]"
    echo "[+] Testing DNS zone transfer for: $domain"
    
    # Récupération des serveurs DNS
    NS_SERVERS=$(dig NS "$domain" +short 2>/dev/null)
    
    if [ -z "$NS_SERVERS" ]; then
        echo "[-] No nameservers found for $domain"
    else
        echo "[+] Found nameservers: $NS_SERVERS"
        VULNERABLE=false
        
        for NS in $NS_SERVERS; do
            echo "[+] Testing $NS..."
            
            # Tentative de zone transfer
            RESULT=$(dig AXFR @"$NS" "$domain" 2>/dev/null)
            
            if echo "$RESULT" | grep -q "Transfer failed\|connection timed out\|communications error"; then
                echo "[-] Zone transfer failed on $NS"
            elif [ $(echo "$RESULT" | wc -l) -gt 10 ]; then
                echo "[!] VULNERABLE: Zone transfer successful on $NS"
                echo "$RESULT" > "dns_scan/zone_transfer_${NS//./_}.txt"
                echo "$RESULT" | head -5
                echo "[...] Full output saved to: dns_scan/zone_transfer_${NS//./_}.txt"
                VULNERABLE=true
            else
                echo "[-] Zone transfer failed on $NS"
            fi
        done
        
        if $VULNERABLE; then
            echo "[!] Domain $domain is VULNERABLE to DNS zone transfer!"
        else
            echo "[✓] Domain $domain is safe from DNS zone transfer"
        fi
    fi
fi    


# ==============================
# 🔄 SUBDOMAIN ENUMERATION
# ==============================
if [[ ! -f "checkpoints/subdomain_enum_done" ]] || [[ "$LAST_STAGE" == "dmarc" ]]; then
    # Choix de la méthode d'énumération
    echo "Choose enumeration method:"
    echo "1) bbot (full scan with -f)"
    echo "2) subfinder + assetfinder"
    echo "3) All methods combined"
    echo "4) No subdomain enumeration (use main domain only)"
    read -p "Enter choice (1, 2, 3 or 4): " enum_choice

    echo "[+]------ Starting Subdomain Enumeration ------[+]"

    case $enum_choice in
        1)
            if command -v bbot &>/dev/null; then
                echo "[+] Running bbot full scan..."
                bbot -t "$domain" -f subdomain-enum -y --output-dir bbot_output
                find bbot_output -name "*.txt" -exec cat {} \; | grep -E ".*\.$domain" \
                  | sed 's/^https\?:\/\///' | sed 's/\/.*$//' | sort -u > subdomains.txt
            else
                echo "[!] bbot not found, falling back to option 2"
                enum_choice=2
            fi
            ;;
        2)
            echo "[+] Running subfinder + assetfinder"
            subfinder -d "$domain" -silent > subdomains_temp1.txt
            if command -v assetfinder &>/dev/null; then
                assetfinder --subs-only "$domain" > subdomains_temp2.txt 2>/dev/null
            else
                touch subdomains_temp2.txt
            fi
            cat subdomains_temp1.txt subdomains_temp2.txt  | sort -u > subdomains.txt
            rm -f subdomains_temp1.txt subdomains_temp2.txt 
            ;;
        3)
            echo "[+] Running all enumeration methods..."
            # Subfinder
            subfinder -d "$domain" -silent > subdomains_all.txt
            # Assetfinder
            if command -v assetfinder &>/dev/null; then
                assetfinder --subs-only "$domain" >> subdomains_all.txt 2>/dev/null
            fi

            # Bbot si disponible
            if command -v bbot &>/dev/null; then
                bbot -t "$domain" -f subdomain-enum -y --output-dir bbot_output_temp 2>/dev/null
                find bbot_output_temp -name "*.txt" -exec cat {} \; | grep -E ".*\.$domain" \
                  | sed 's/^https\?:\/\///' | sed 's/\/.*$//' >> subdomains_all.txt 2>/dev/null
                rm -rf bbot_output_temp
            fi
            sort -u subdomains_all.txt > subdomains.txt
            rm -f subdomains_all.txt
            ;;
        4)
            echo "[+] Using main domain only (no subdomain enumeration)"
            echo "$domain" > subdomains.txt
            ;;
        *)
            echo "[!] Invalid choice, using main domain only"
            echo "$domain" > subdomains.txt
            ;;
    esac

    # Final fallback - au minimum le domaine principal
    if [[ ! -s subdomains.txt ]]; then
        echo "[!] No subdomains found, using main domain only"
        echo "$domain" > subdomains.txt
    fi

    echo "[+] Domains to scan: $(wc -l < subdomains.txt)"
    echo "[+] Sample:"
    head -5 subdomains.txt
    touch checkpoints/subdomain_enum_done
    save_checkpoint "subdomain_enum"
fi
# ==============================
# 🌐 ACTIVE SUBDOMAIN DISCOVERY
# ==============================
if [[ ! -f "checkpoints/active_subdomains_done" ]] || [[ "$LAST_STAGE" == "subdomain_enum" ]]; then
    echo "[+] Checking for Alive Subdomains..."
    
    # Pour l'option 4, tester directement le domaine
    if [[ "$enum_choice" == "4" ]]; then
        echo "[+] Option 4: Testing single domain $domain directly..."
        
        # Méthode 1: Utiliser echo avec pipe
        echo "https://$domain" | httpx \
          -p 80,443,8080,8443,8000,3000,5000,9000 \
          -title -tech-detect -server \
          -status-code -web-server \
          -follow-redirects -threads 100 -timeout 10 \
          -silent > alive_detailed.txt 2>/dev/null || true
        
        # Si vide, essayer sans https
        if [[ ! -s alive_detailed.txt ]]; then
            echo "[+] Trying HTTP protocol..."
            echo "http://$domain" | httpx \
              -p 80,443,8080,8443,8000,3000,5000,9000 \
              -title -tech-detect -server \
              -status-code -web-server \
              -follow-redirects -threads 100 -timeout 10 \
              -silent >> alive_detailed.txt 2>/dev/null || true
        fi
        
        # Si toujours vide, forcer l'ajout du domaine
        if [[ ! -s alive_detailed.txt ]]; then
            echo "[!] httpx returned empty, manually adding domain as alive"
            echo "https://$domain [MANUALLY_ADDED]" > alive_detailed.txt
        fi
    else
        # Comportement normal pour les autres options
        httpx -l subdomains.txt \
          -p 80,443,8080,8443,8000,3000,5000,9000 \
          -title -tech-detect -server \
          -status-code -web-server \
          -follow-redirects -threads 100 -timeout 10 \
          -o alive_detailed.txt
    fi

    # Traitement des résultats
    if [[ -s alive_detailed.txt ]]; then
        cat alive_detailed.txt | awk '{print $1}' | grep -v "MANUALLY_ADDED" > all_urls.txt
        grep "^https://" all_urls.txt > alive.txt 2>/dev/null || true
        grep "^http://" all_urls.txt > http_urls.txt 2>/dev/null || true
        
        echo "[+] Alive domains found: $(wc -l < alive.txt 2>/dev/null || echo 0)"
        cat alive.txt 2>/dev/null || echo "https://$domain" > alive.txt
    else
        echo "[!] No alive domains detected, using main domain as fallback"
        echo "https://$domain" > alive.txt
    fi

    # S'assurer qu'au moins le domaine principal est dans alive.txt
    if [[ ! -s alive.txt ]]; then
        echo "https://$domain" > alive.txt
    fi

    echo "[+] Final alive domains:"
    cat alive.txt

    touch checkpoints/active_subdomains_done
    save_checkpoint "active_subdomains"
fi

# ==============================
# 🛡️ WAF DETECTION - DOMAINE PRINCIPAL SEULEMENT
# ==============================
if [[ ! -f "checkpoints/waf_done" ]] || [[ "$LAST_STAGE" == "active_subdomains" ]]; then
    echo "[+]------ WAF Detection (Main Domain Only) ------[+]"
    if command -v wafw00f &>/dev/null; then
        echo "[+] Scanning main domain for WAF protection..."
        mkdir -p waf_detection
        wafw00f "https://$domain" -o "waf_detection/${domain}_waf.txt" 2>/dev/null
        
        # Vérifier le résultat
        if [ -s "waf_detection/${domain}_waf.txt" ]; then
            echo "[+] WAF detection completed for $domain"
            cat "waf_detection/${domain}_waf.txt" | grep -E "is behind|is protected" | head -1
        else
            echo "[!] No WAF detected or error in scan"
        fi
    else
        echo "[!] wafw00f not installed. Install with: pip install wafw00f"
        mkdir -p waf_detection
        touch "waf_detection/${domain}_waf.txt"
    fi
    touch checkpoints/waf_done
    save_checkpoint "waf"
fi

# ==============================
# 🎯 WORDPRESS DETECTION & FILTERING
# ==============================
if [[ ! -f "checkpoints/wordpress_done" ]] || [[ "$LAST_STAGE" == "waf" ]]; then
    echo "[+]------ WordPress Detection ------[+]"

    # Méthode 1: Via les technos détectées par httpx
    echo "[+] Filtering WordPress sites from httpx results..."
    grep -i "wordpress" alive_detailed.txt | awk '{print $1}' > wordpress_sites.txt 2>/dev/null || true

    touch checkpoints/wordpress_done
    save_checkpoint "wordpress"
fi

# ==============================
# 💾 GOWITNESS - DB ONLY MODE
# ==============================
if [[ ! -f "checkpoints/gowitness_done" ]] || [[ "$LAST_STAGE" == "wordpress" ]]; then
    echo "[+]------ GOWITNESS DB ONLY MODE ------[+]"

    # Vérifier si gowitness est installé
    if ! command -v gowitness &>/dev/null; then
        echo "[!] Gowitness not found. Installing..."
        go install github.com/sensepost/gowitness@latest
        export PATH=$PATH:$(go env GOPATH)/bin
    fi

    # Générer un nom de DB unique avec timestamp
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    GOWITNESS_DB="gowitness_${domain}_${TIMESTAMP}.db"

    if command -v gowitness &>/dev/null; then
        echo "[+] Storing results in $GOWITNESS_DB..."
        
        gowitness scan file -f alive.txt \
            --threads 5 \
            --timeout 30 \
            --write-db \
            --write-db-uri "sqlite://$GOWITNESS_DB"
        
        echo "[✅] Done! Results stored in $GOWITNESS_DB"
        
        # 🔧 TROUVER UN PORT LIBRE AUTOMATIQUEMENT
        find_available_port() {
            for port in {8081..8100}; do
                if ! lsof -ti:$port >/dev/null 2>&1; then
                    echo $port
                    return
                fi
            done
            echo "8081"  # Fallback
        }
        
        PORT=$(find_available_port)
        
        echo "[+] Starting gowitness server on port $PORT..."
        
        # Arrêter seulement les anciens processus gowitness (pas de sudo)
        pkill -f "gowitness.*report server.*$PORT" 2>/dev/null || true
        sleep 2
        
        # Démarrer le nouveau server
        gowitness report server --db-uri "sqlite://$GOWITNESS_DB" --port "$PORT" --quiet &
        GOWITNESS_PID=$!
        
        sleep 2  # Attendre le démarrage
        
        if kill -0 $GOWITNESS_PID 2>/dev/null; then
            echo "[✅] Gowitness server started with PID: $GOWITNESS_PID"
            echo "[🌐] Access screenshots at: http://localhost:$PORT"
            echo "[💾] Database: $GOWITNESS_DB"
            
            # Sauvegarder les infos pour plus tard (dans le dossier courant)
            echo "$PORT:$GOWITNESS_PID:$GOWITNESS_DB" > current_gowitness_server.txt
        else
            echo "[❌] Failed to start gowitness server on port $PORT"
            echo "[💡] You can manually start it with:"
            echo "     gowitness report server --db-uri \"sqlite://$GOWITNESS_DB\" --port 8081"
        fi
    else
        echo "[❌] Gowitness not found"
    fi

    # NE PAS SUPPRIMER subdomains.txt - garder pour référence
    echo "[+] Keeping subdomains.txt for future analysis"
    touch checkpoints/gowitness_done
    save_checkpoint "gowitness"
fi

# ==============================
# 🔄 SUBDOMAIN TAKEOVER CHECK
# ==============================
if [[ ! -f "checkpoints/subdomain_takeover_done" ]] || [[ "$LAST_STAGE" == "gowitness" ]]; then
    # Check for Subdomain Takeover using Subzy
    echo "[+] Checking for Subdomain Takeover [+]"
    if command -v subzy &>/dev/null; then
        subzy run --targets alive.txt > special_scans/subzy_results.txt 2>/dev/null || echo "[!] Subzy scan completed with warnings"
    else
        echo "[!] Subzy not found, skipping subdomain takeover check"
        touch special_scans/subzy_results.txt
    fi
    touch checkpoints/subdomain_takeover_done
    save_checkpoint "subdomain_takeover"
fi

# ==============================
# ☁️ CLOUD BUCKET TESTING
# ==============================
if [[ ! -f "checkpoints/cloud_buckets_done" ]] || [[ "$LAST_STAGE" == "subdomain_takeover" ]]; then
    echo "[+]------ Cloud Bucket Testing ------[+]"
    
    # S3 Buckets
    echo "[+] Testing for S3 buckets..."
    {
        # Test common S3 bucket names
        echo "s3.$domain"
        echo "$domain.s3.amazonaws.com"
        echo "assets.$domain"
        echo "storage.$domain"
        echo "media.$domain"
        echo "backup.$domain"
        echo "data.$domain"
        echo "logs.$domain"
        echo "prod.$domain"
        echo "dev.$domain"
        echo "test.$domain"
        echo "$domain-prod"
        echo "$domain-staging"
        echo "$domain-dev"
    } > cloud_buckets/bucket_names.txt
    
    cat alive.txt | grep 's3.amazonaws.com' >> cloud_buckets/bucket_names.txt

    # Test S3 buckets avec curl
    while read -r bucket; do
        echo "[+] Testing S3 bucket: $bucket"
        curl -I "http://$bucket.s3.amazonaws.com" 2>/dev/null | head -1 >> cloud_buckets/s3_results.txt
        curl -I "https://$bucket.s3.amazonaws.com" 2>/dev/null | head -1 >> cloud_buckets/s3_results.txt
    done < cloud_buckets/bucket_names.txt

    # Utiliser cloud_enum si disponible
    if command -v cloud_enum &>/dev/null; then
        echo "[+] Running cloud_enum for comprehensive cloud bucket discovery..."
        cloud_enum -k "$domain" -l "cloud_buckets/cloud_enum_$domain.txt" 2>/dev/null || echo "[!] cloud_enum completed with warnings"
    fi

    # Utiliser s3scanner si disponible
    if command -v s3scanner &>/dev/null; then
        echo "[+] Running s3scanner..."
        s3scanner scan --buckets-file cloud_buckets/bucket_names.txt --out-file "cloud_buckets/s3scanner_$domain.txt" 2>/dev/null || echo "[!] s3scanner completed with warnings"
    fi

    # Test Google Cloud Storage
    echo "[+] Testing Google Cloud Storage buckets..."
    while read -r bucket; do
        echo "[+] Testing GCS bucket: $bucket"
        curl -I "https://storage.googleapis.com/$bucket" 2>/dev/null | head -1 >> cloud_buckets/gcs_results.txt
    done < cloud_buckets/bucket_names.txt

    # Test Azure Blob Storage
    echo "[+] Testing Azure Blob Storage..."
    while read -r bucket; do
        echo "[+] Testing Azure blob: $bucket"
        curl -I "https://$bucket.blob.core.windows.net" 2>/dev/null | head -1 >> cloud_buckets/azure_results.txt
    done < cloud_buckets/bucket_names.txt

    echo "[+] Cloud bucket testing completed"
    touch checkpoints/cloud_buckets_done
    save_checkpoint "cloud_buckets"
fi

# ==============================
# 🔍 ENDPOINT DISCOVERY
# ==============================
if [[ ! -f "checkpoints/endpoint_discovery_done" ]] || [[ "$LAST_STAGE" == "cloud_buckets" ]]; then
    echo "[+]------ Endpoint Discovery ------[+]"

    echo "[+] Extracting Endpoints using Katana [+]"
    if command -v katana &>/dev/null; then 
        echo "[+] Running Katana with optimized parameters..." 
        
        # ADAPTATION POUR L'OPTION 4 - seulement le domaine principal
        if [[ "$enum_choice" == "4" ]]; then
            echo "[+] Option 4 selected: Scanning only main domain $domain"
            katana -u "https://$domain" -jc -aff -silent -c 80 -d 2 -f qurl -o katana_endpoints.txt 2>/dev/null || {
                echo "[!] Katana execution failed, creating empty file"
                touch katana_endpoints.txt
            }
        else
            # Comportement normal avec tous les sous-domaines
            katana -list alive.txt -jc -aff -silent -c 80 -d 2 -f qurl -o katana_endpoints.txt 2>/dev/null || {
                echo "[!] Katana execution failed, creating empty file"
                touch katana_endpoints.txt
            }
        fi
    else
        echo "[!] Katana not found, skipping..."
        touch katana_endpoints.txt
    fi

    echo "[+] Using gau with threads [+]"
    if command -v gau &>/dev/null; then
        # ADAPTATION POUR L'OPTION 4 - limiter gau au domaine principal
        if [[ "$enum_choice" == "4" ]]; then
            echo "[+] Option 4: GAU scanning only $domain"
            echo "$domain" | gau --threads 30 > gau_endpoints.txt
        else
            cat alive.txt | gau --threads 30 --subs > gau_endpoints.txt
        fi
        echo "[+] GAU endpoints found: $(wc -l < gau_endpoints.txt)"
    else
        echo "[!] GAU not installed, install with: go install github.com/lc/gau/v2/cmd/gau@latest"
        touch gau_endpoints.txt
    fi

    # Filtering Katana Endpoints
    echo "[+] Filtering Katana Endpoints & removing extra spaces [+]"

    # Function to remove spaces from URLs in a text file
    remove_spaces_from_urls() {
        local file_path="katana_endpoints.txt"

        # Check if the file exists
        if [[ ! -f "$file_path" ]]; then
            echo "Error: The file was not found."
            touch katana_endpoints_filtered.txt
            return
        fi

        # Output file where modified URLs will be stored
        output_file="katana_endpoints_filtered.txt"

        # Process each line (URL) and remove spaces within the URL
        while IFS= read -r line; do
            modified_url="${line// /}" # Remove spaces from the URL
            echo "$modified_url" >> "$output_file"
        done < "$file_path"

        echo "Filtered URLs have been saved to: $output_file"
    }

    # Call the function to process the file
    remove_spaces_from_urls

    # ⭐⭐⭐ COMBINE ALL ENDPOINT SOURCES ⭐⭐⭐
    echo "[+] Combining all endpoints sources..."
    {
        cat katana_endpoints_filtered.txt 2>/dev/null
        cat gau_endpoints.txt 2>/dev/null
    } | sort -u > all_endpoints.txt

    # Alternative avec urldedupe si disponible
    if command -v urldedupe &>/dev/null; then
        echo "[+] Using urldedupe for better URL deduplication..."
        cat all_endpoints.txt | urldedupe > all_endpoints_deduped.txt 2>/dev/null
        mv all_endpoints_deduped.txt all_endpoints.txt 2>/dev/null || true
    fi

    # ADAPTATION: Filtrer pour garder seulement le domaine principal si option 4
    if [[ "$enum_choice" == "4" ]]; then
        echo "[+] Option 4: Filtering endpoints to keep only $domain"
        grep "$domain" all_endpoints.txt > all_endpoints_filtered.txt 2>/dev/null
        mv all_endpoints_filtered.txt all_endpoints.txt 2>/dev/null || true
    fi

    # Create allurls.txt for compatibility with your commands
    cp all_endpoints.txt allurls.txt

    # ⭐⭐⭐ EXTRACT URLS WITH PARAMETERS ⭐⭐⭐
    echo "[+] Extracting URLs with parameters..."
    cat all_endpoints.txt 2>/dev/null | grep -E '\?[^=]+=' | sort -u > params.txt
    echo "[+] URLs with parameters found: $(wc -l < params.txt 2>/dev/null || echo 0)"
    touch checkpoints/endpoint_discovery_done
    save_checkpoint "endpoint_discovery"
fi
# ==============================
# 📁 SENSITIVE FILES DETECTION
# ==============================
if [[ ! -f "checkpoints/sensitive_files_done" ]] || [[ "$LAST_STAGE" == "endpoint_discovery" ]]; then
    # ⭐⭐⭐ SENSITIVE FILES DETECTION ⭐⭐⭐
    echo "[+] Searching for sensitive files..."
    cat allurls.txt 2>/dev/null | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$" > sensitive_files/sensitive_files.txt 2>/dev/null || true
    echo "[+] Sensitive files found: $(wc -l < sensitive_files/sensitive_files.txt 2>/dev/null || echo 0)"

    # ⭐⭐⭐ CHECK SENSITIVE FILES WITH HTTPX FOR 404 STATUS ⭐⭐⭐
    echo "[+] Checking which sensitive files return 404 status..."
    if [[ -s "sensitive_files/sensitive_files.txt" ]]; then
        httpx -l sensitive_files/sensitive_files.txt -status-code -mc 404 -o sensitive_files/sensitive_files_404.txt 2>/dev/null || {
            echo "[!] HTTPX scan for sensitive files failed"
            touch sensitive_files/sensitive_files_404_urls.txt
        }
        
        if [[ -f "sensitive_files/sensitive_files_404.txt" ]]; then
            cat sensitive_files/sensitive_files_404.txt | awk '{print $1}' > sensitive_files/sensitive_files_404_urls.txt 2>/dev/null || true
            echo "[+] Sensitive files returning 404: $(wc -l < sensitive_files/sensitive_files_404_urls.txt 2>/dev/null || echo 0)"
        else
            echo "[!] No sensitive files returned 404 status"
            touch sensitive_files/sensitive_files_404_urls.txt
        fi
    else
        echo "[!] No sensitive files to check"
        touch sensitive_files/sensitive_files_404_urls.txt
    fi
    touch checkpoints/sensitive_files_done
    save_checkpoint "sensitive_files"
fi

# ==============================
# 📜 JAVASCRIPT ANALYSIS
# ==============================
if [[ ! -f "checkpoints/javascript_analysis_done" ]] || [[ "$LAST_STAGE" == "sensitive_files" ]]; then
    # ⭐⭐⭐ JAVASCRIPT ANALYSIS ⭐⭐⭐
    echo "[+]------ Starting JavaScript Analysis ------[+]"

    # First, extract all JavaScript URLs
    echo "[+] Extracting JavaScript files from endpoints..."
    grep -E "\.js($|\?| )" all_endpoints.txt 2>/dev/null | sort -u > js_files.txt

    if [[ -s "js_files.txt" ]]; then
        echo "[+] JavaScript files found: $(wc -l < js_files.txt)"
        
        # Run JSHunter on the JavaScript files
        echo "[+] Running JSHunter analysis..."
        if command -v jshunter &>/dev/null; then
            jshunter -f js_files.txt -o jshunter_results.json 2>/dev/null || echo "[!] JSHunter execution completed with warnings"
            echo "[+] JSHunter analysis completed"
            
            # Convert JSON to readable format if needed
            if [[ -f "jshunter_results.json" ]]; then
                if command -v jq &>/dev/null; then
                    jq '.' jshunter_results.json > jshunter_results_pretty.json 2>/dev/null || true
                fi
                echo "[+] JSHunter results saved to jshunter_results.json"
                
                # Extract interesting findings to a text file
                echo "[+] Extracting key findings from JSHunter results..."
                if command -v jq &>/dev/null; then
                    jq -r '.secrets[]? | "SECRET: \(.type) - \(.value)"' jshunter_results.json > special_scans/jshunter_secrets.txt 2>/dev/null || true
                    jq -r '.urls[]? | "URL: \(.)"' jshunter_results.json > special_scans/jshunter_urls.txt 2>/dev/null || true
                    jq -r '.endpoints[]? | "ENDPOINT: \(.)"' jshunter_results.json > special_scans/jshunter_endpoints.txt 2>/dev/null || true
                fi
            fi
        else
            echo "[!] JSHunter not found, skipping..." 
            echo "[!] You can install it from: https://github.com/s0md3v/JSHunter"
        fi

        # Alternative: Use LinkFinder
        echo "[+] Running LinkFinder on JavaScript files..."
        if command -v linkfinder &>/dev/null; then
            for js_file in js_analysis/*.js; do
                if [[ -f "$js_file" ]]; then
                    linkfinder -i "$js_file" -o cli >> special_scans/linkfinder_results.txt 2>/dev/null || true
                fi
            done
        fi
    else
        echo "[!] No JavaScript files found for analysis"
        touch jshunter_results.json
    fi
    touch checkpoints/javascript_analysis_done
    save_checkpoint "javascript_analysis"
fi

# ==============================
# 🛡️ NUCLEI SCANS
# ==============================
if [[ ! -f "checkpoints/nuclei_done" ]] || [[ "$LAST_STAGE" == "javascript_analysis" ]]; then
    # ⭐⭐⭐ NUCLEI SCANS ⭐⭐⭐
    echo "[+]------ Starting Nuclei Scans ------[+]"

    if command -v nuclei &>/dev/null; then
        # Update nuclei templates if first run
        if [[ ! -f "checkpoints/nuclei_updated" ]]; then
            echo "[+] Updating Nuclei templates..."
            nuclei -update-templates -silent 2>/dev/null || echo "[!] Template update completed with warnings"
            touch checkpoints/nuclei_updated
        fi

        # Nuclei CVEs scan
        echo "[+] Running Nuclei CVEs scan (2018-2025)..."
        if [[ -d "/home/skyle/tools/nucleicves" ]]; then
            nuclei -l alive.txt -t /home/skyle/tools/nucleicves/2018/ -t /home/skyle/tools/nucleicves/2019/ -t /home/skyle/tools/nucleicves/2020/ -t /home/skyle/tools/nucleicves/2021/ -t /home/skyle/tools/nucleicves/2022/ -t /home/skyle/tools/nucleicves/2023/ -t /home/skyle/tools/nucleicves/2024/ -t /home/skyle/tools/nucleicves/2025/ -c 100 -bs 100 -rl 300 -o nuclei_results/cves_scan.txt 2>/dev/null || echo "[!] Nuclei CVE scan completed with warnings"
        else
            echo "[!] Nucleicves directory not found, using built-in CVE templates"
            nuclei -l alive.txt -t cves/ -c 50 -rl 150 -o nuclei_results/cves_scan.txt 2>/dev/null || echo "[!] Nuclei CVE scan completed with warnings"
        fi

        # JavaScript credentials disclosure
        echo "[+] Checking JavaScript files for credentials disclosure..."
        if [[ -f "/home/skyle/tools/privatenucleiteplates/credentials-disclosure-all.yaml" ]]; then
            cat allurls.txt 2>/dev/null | grep -E "\.js$" | nuclei -t /home/skyle/tools/privatenucleiteplates/credentials-disclosure-all.yaml -c 30 -o nuclei_results/js_credentials.txt 2>/dev/null || true
        else
            echo "[!] credentials-disclosure-all.yaml not found, skipping JS credentials check"
            touch nuclei_results/js_credentials.txt
        fi

        # CORS scan
        echo "[+] Checking for CORS misconfigurations..."
        if [[ -f "/home/skyle/tools/privatenucleiteplates/cors.yaml" ]]; then
            cat alive.txt | nuclei -t /home/skyle/tools/privatenucleiteplates/cors.yaml -o nuclei_results/cors_results.txt 2>/dev/null || true
        else
            echo "[!] cors.yaml not found, skipping CORS check"
            touch nuclei_results/cors_results.txt
        fi

        # All templates scan
        echo "[+] Running Nuclei automatic scan (via stdin)..."
        if [[ -s "alive.txt" ]]; then
            cat alive.txt | nuclei -as -c 50 -rl 150 -o nuclei_results/nuclei_all_templates.txt 2>/dev/null || echo "[!] Nuclei automatic scan completed with warnings"
            echo "[+] Automatic scan completed"
        else
            echo "[!] No alive URLs to scan"
            touch nuclei_results/nuclei_all_templates.txt
        fi

        # Additional security scans
        echo "[+] Running additional security scans..."
        nuclei -l alive.txt -t exposures/ -t misconfiguration/ -c 30 -o nuclei_results/exposures_misconfig.txt 2>/dev/null || true
        nuclei -l alive.txt -t vulnerabilities/ -c 30 -o nuclei_results/vulnerabilities.txt 2>/dev/null || true
    else
        echo "[!] Nuclei not found, skipping all Nuclei scans"
        touch nuclei_results/cves_scan.txt
        touch nuclei_results/js_credentials.txt
        touch nuclei_results/cors_results.txt
        touch nuclei_results/nuclei_all_templates.txt
        touch nuclei_results/exposures_misconfig.txt
        touch nuclei_results/vulnerabilities.txt
    fi

    # Git directory detection
    echo "[+] Checking for exposed .git directories..."
    cat alive.txt | httpx -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe -o special_scans/git_exposure.txt 2>/dev/null || echo "[!] Git exposure check completed with warnings"
    touch checkpoints/nuclei_done
    save_checkpoint "nuclei"
fi


# ==============================
# 🎯 GF PATTERNS & EXPLOITATION
# ==============================
if [[ ! -f "checkpoints/gf_patterns_done" ]] || [[ "$LAST_STAGE" == "nuclei" ]]; then
    # ⭐⭐⭐ GF PATTERNS & EXPLOITATION ⭐⭐⭐
    echo "[+]------ Starting GF Patterns & Exploitation ------[+]"

    if command -v gf &>/dev/null; then
        # SQL Injection
        echo "[+] Testing for SQL Injection..."
        cat params.txt | gf sqli > gf_patterns/sqli.txt 2>/dev/null || true
        if command -v nuclei &>/dev/null; then
            nuclei -l gf_patterns/sqli.txt -t /home/skyle/tools/privatenucleiteplates/errsqli.yaml -dast -o nuclei_results/sqli_nuclei.txt 2>/dev/null || true
        fi

        # XSS
        echo "[+] Testing for XSS vulnerabilities..."
        if command -v urldedupe &>/dev/null; then
            cat params.txt | gf xss | urldedupe > gf_patterns/xss_urls.txt 2>/dev/null || true
        else
            cat params.txt | gf xss | sort -u > gf_patterns/xss_urls.txt 2>/dev/null || true
        fi
        
        if command -v Gxss &>/dev/null && command -v kxss &>/dev/null; then
           cat gf_patterns/xss_urls.txt | Gxss | kxss | tee gf_patterns/xss_output.txt 2>/dev/null || echo "[!] XSS testing completed with warnings"
        else
           echo "[!] Gxss or kxss not found, skipping..."
        fi

	echo "[+] Starting high-speed LFI scanning..."
	cat gf_patterns/lfi_urls.txt | qsreplace "FUZZ" | sort -u > gf_patterns/lfi_targets.txt

	cat gf_patterns/lfi_targets.txt | parallel -j 10 ffuf -u {} \
  	-w /home/skyle/tools/privatenucleiteplates/loxs/payloads/lfishort.txt \
  	-H "User-Agent: Mozilla/5.0" \
  	-mr "root:" \
  	-mc 200 \
  	-fs 0 \
  	-o gf_patterns/lfi_ffuf_results_{#}.txt

	# SSRF
	echo "[+] Testing for SSRF vulnerabilities..."
	cat params.txt | gf ssrf > gf_patterns/ssrf_urls.txt 2>/dev/null || true
	if command -v nuclei &>/dev/null; then
		    nuclei -l gf_patterns/ssrf_urls.txt -t /home/skyle/nuclei-templates/dast/vulnerabilities/ssrf/response-ssrf.yaml -dast -o nuclei_results/ssrf_nuclei.txt 2>/dev/null || true
        fi
         
        # CRLF
        echo "[+] Testing for CRLF vulnerabilities..."
        if command -v nuclei &>/dev/null; then
            nuclei -l alive.txt -t /home/skyle/tools/privatenucleiteplates/cRlf.yaml -o nuclei_results/crlf_nuclei.txt 2>/dev/null || true
        fi
        
        # Open Redirect
        echo "[+] Testing for Open Redirect vulnerabilities..."
        cat params.txt | gf redirect > gf_patterns/redirect_urls.txt 2>/dev/null || true
        if command -v nuclei &>/dev/null && [[ -f "/home/skyle/tools/privatenucleiteplates/openRedirect.yaml" ]]; then
            nuclei -l gf_patterns/redirect_urls.txt -t /home/skyle/tools/privatenucleiteplates/openRedirect.yaml -o nuclei_results/openredirect_nuclei.txt 2>/dev/null || true
        fi

    else
        echo "[!] GF not found, skipping GF patterns"
        touch gf_patterns/sqli.txt
        touch gf_patterns/xss_urls.txt
        touch gf_patterns/lfi_urls.txt
        touch gf_patterns/ssrf_urls.txt
        touch gf_patterns/redirect_urls.txt
    fi
    touch checkpoints/gf_patterns_done
    save_checkpoint "gf_patterns"
fi


# ==============================
# 🏁 FINAL CLEANUP AND REPORT
# ==============================
if [[ ! -f "checkpoints/final_done" ]] || [[ "$LAST_STAGE" == "github_recon" ]]; then
    # ⭐⭐⭐ GENERATE SUMMARY REPORT ⭐⭐⭐
    echo "[+] Generating summary report..."
    {
        echo "=== RECONNAISSANCE SUMMARY REPORT ==="
        echo "Domain: $domain"
        echo "Scan Date: $(date)"
        echo ""
        echo "=== SUBDOMAIN STATISTICS ==="
        echo "Total subdomains found: $(wc -l < subdomains.txt 2>/dev/null || echo 0)"
        echo "Active subdomains: $(wc -l < alive.txt 2>/dev/null || echo 0)"
        echo "HTTP URLs: $(wc -l < http_urls.txt 2>/dev/null || echo 0)"
        echo "HTTPS URLs: $(wc -l < alive.txt 2>/dev/null || echo 0)"
        echo ""
        echo "=== ENDPOINT STATISTICS ==="
        echo "All unique endpoints: $(wc -l < all_endpoints.txt 2>/dev/null || echo 0)"
        echo "URLs with parameters: $(wc -l < params.txt 2>/dev/null || echo 0)"
        echo "JavaScript files: $(wc -l < js_files.txt 2>/dev/null || echo 0)"
        echo ""
        echo "=== SECURITY FINDINGS ==="
        echo "Sensitive files: $(wc -l < sensitive_files/sensitive_files.txt 2>/dev/null || echo 0)"
        echo "Sensitive files (404): $(wc -l < sensitive_files/sensitive_files_404_urls.txt 2>/dev/null || echo 0)"
        echo "WordPress sites: $(wc -l < wordpress_sites.txt 2>/dev/null || echo 0)"
        echo ""
        echo "=== SCAN RESULTS LOCATIONS ==="
        echo "Nuclei results: nuclei_results/"
        echo "GF patterns: gf_patterns/"
        echo "Sensitive files: sensitive_files/"
        echo "Special scans: special_scans/"
        echo "Cloud buckets: cloud_buckets/"
        echo "GitHub recon: github_recon/"
        echo "Wayback data: wayback_data/"
        echo "DMARC check: dmarc_check/"
        echo "Web screenshots: web_screenshots/ (via Gowitness DB)"
    } > RECON_SUMMARY.txt

    # Cleanup temporary files (keep important ones)
    rm -f gau_endpoints.txt katana_endpoints.txt katana_endpoints_filtered.txt allurls.txt
    echo "[+] Cleaned up temporary files [+]"

    echo "[-] Enhanced Recon Completed [-]"
    echo "[+] Final summary saved to: RECON_SUMMARY.txt"
    echo "[+] Key findings:"
    echo "    - Subdomains: $(wc -l < subdomains.txt 2>/dev/null || echo 0)"
    echo "    - Active URLs: $(wc -l < alive.txt 2>/dev/null || echo 0)"
    echo "    - Endpoints: $(wc -l < all_endpoints.txt 2>/dev/null || echo 0)"
    echo "    - Cloud buckets tested: $(wc -l < cloud_buckets/bucket_names.txt 2>/dev/null || echo 0)"
    echo "    - Security scans completed in nuclei_results/"
    
    # Display Gowitness info if available
    if [[ -f "current_gowitness_server.txt" ]]; then
        GOWITNESS_INFO=$(cat current_gowitness_server.txt)
        PORT=$(echo "$GOWITNESS_INFO" | cut -d: -f1)
        PID=$(echo "$GOWITNESS_INFO" | cut -d: -f2)
        DB=$(echo "$GOWITNESS_INFO" | cut -d: -f3)
        echo "[🌐] Gowitness server running on: http://localhost:$PORT (PID: $PID)"
        echo "[💾] Screenshots database: $DB"
    fi
    
    touch checkpoints/final_done
    save_checkpoint "completed"
fi
