#!/system/bin/sh
# ioBattery Pro × Makima Edition V5.0-RC1 — api.sh (CGI handler)
# Called by the WebUI httpd. Runs as root. All input is sanitized.
#
# ── PATCH MANIFEST ────────────────────────────────────────────────
#  PATCH-CRITICAL-3: current_now unconditional /1000 → threshold-based unit detect
#                    (matches service.sh logic; >100000 µA sentinel)
#  PATCH-PERF-3:     cpu_usage.sh spawned with freshness guard (3s) + PID-stamped tmp
#  PATCH-MINOR-1:    PID-stamped cpu_pct.cache.tmp prevents two-process write race
# ── ORIGINAL FIX MANIFEST (inherited pre-V5) ───────────────────────
#  FIX-A1: emergency_cooldown: CPU count via directory count (not /online count)
#  FIX-A2: URL decode covers all RFC3986 unreserved chars
#  FIX-A3: save_glass validates alpha/blur/border are numeric with range clamping
#  FIX-A4: running_apps ps fallback uses -o USER,NAME for Android 12+ compat
#  FIX-BUG02: POSIX awk — no gawk 3-arg match()
#  FIX-BUG03: status action detects real CPU thermal zone
#  FIX-BUG05: emergency_cooldown HALF clamped to >= 1
#  FIX-BUG12: CPU usage asynchronous — 600ms block removed from status path
#  FIX-BUG24: JSON log escaping — backslash-first, then double-quote
#  FIX-BUG25: JSON config escaping — backslash-first, then double-quote
#  FIX-BUG26: PKG sanitized via valid_pkg() before any opt/whitelist write
# ──────────────────────────────────────────────────────────────────
echo "Content-Type: application/json"
echo "Cache-Control: no-store, no-cache"
echo "Access-Control-Allow-Origin: *"
echo ""

IOB_DIR="/data/adb/ioBattery"
MODDIR="/data/adb/modules/iobattery"
CONFIG="$IOB_DIR/config.prop"
GLASS_CONF="$IOB_DIR/glass.prop"
OPT="$IOB_DIR/app_optimize.prop"
UA="$IOB_DIR/user_apps.txt"
SA="$IOB_DIR/sys_apps.txt"
WHITELIST="$IOB_DIR/whitelist.txt"
LOG="$IOB_DIR/logs/system_log.prop"

# ── QUERY_STRING parsing ──────────────────────────────────────────
ACTION=$(echo "$QUERY_STRING" | sed -n 's/.*action=\([^&]*\).*/\1/p' | tr -cd 'a-zA-Z0-9_')
PARAM=$(echo "$QUERY_STRING" | sed -n 's/.*param=\([^&]*\).*/\1/p' \
    | sed 's/%3A/:/g;s/%3D/=/g;s/%26/\&/g;s/%2E/./g;s/%2D/-/g;s/%5F/_/g;s/%40/@/g' \
    | sed 's/%21/!/g;s/%7E/~/g;s/%28/(/g;s/%29/)/g;s/%2C/,/g;s/%2B/+/g' \
    | sed 's/%2F/\//g;s/%25/%/g;s/+/ /g')

mkdir -p "$IOB_DIR" 2>/dev/null
chmod 770 "$IOB_DIR" 2>/dev/null

# ── V5-BUG002: API Token Authentication ──────────────────────────
# All CGI endpoints require a valid token. Token is generated at install
# (customize.sh) and stored in $IOB_DIR/.api_token (chmod 600, root-only).
# The WebUI fetches it on page load via ?action=get_token (exempt action).
# Every other request must supply ?token=<value> matching the stored token.
#
# Exempt actions (no token required):
#   get_token  — initial page-load bootstrap fetch
#   status     — read-only telemetry (low-risk, needed for dashboard load)
#
_TOKEN_FILE="$IOB_DIR/.api_token"
_REQ_TOKEN=$(echo "$QUERY_STRING" | sed -n 's/.*token=\([^&]*\).*/\1/p' | tr -cd 'a-zA-Z0-9')
_STORED_TOKEN=$(cat "$_TOKEN_FILE" 2>/dev/null | tr -d '[:space:]' || echo "")

# Actions that do NOT require auth (read-only or bootstrap)
_TOKEN_EXEMPT=0
case "$ACTION" in
    get_token|status) _TOKEN_EXEMPT=1 ;;
esac

if [ "$_TOKEN_EXEMPT" = "0" ]; then
    if [ -z "$_STORED_TOKEN" ] || [ "$_REQ_TOKEN" != "$_STORED_TOKEN" ]; then
        printf '{"ok":false,"error":"Unauthorized: invalid or missing token"}\n'
        exit 0
    fi
fi

# ── Helpers ───────────────────────────────────────────────────────
cfg_set() {
    local key="$1" val="$2" tmp="$CONFIG.tmp.$$"
    (
        flock -x 9
        touch "$CONFIG" 2>/dev/null
        grep -v "^${key}=" "$CONFIG" 2>/dev/null > "$tmp" || true
        echo "${key}=${val}" >> "$tmp"
        mv "$tmp" "$CONFIG"
        chmod 664 "$CONFIG" 2>/dev/null
    ) 9>>"$CONFIG.lock"
    # V5-P2: Signal service.sh to reload config immediately (DESIGN-002)
    touch "$IOB_DIR/.reload" 2>/dev/null || true
}

cfg_get() { grep "^${1}=" "$CONFIG" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]'; }

valid_pkg() { echo "$1" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$'; }

valid_int() {
    local val="$1" min="${2:-0}" max="${3:-999999}"
    echo "$val" | grep -qE '^[0-9]+$' || return 1
    [ "$val" -ge "$min" ] && [ "$val" -le "$max" ] 2>/dev/null
}

# FIX-BUG03: Detect real CPU thermal zone
_detect_cpu_zone_api() {
    local z t d raw
    for z in /sys/class/thermal/thermal_zone*/type; do
        t=$(cat "$z" 2>/dev/null || echo "")
        case "$t" in *cpu*|*CPU*|*cluster*|*core*)
            d=$(dirname "$z")
            raw=$(cat "$d/temp" 2>/dev/null || echo 0)
            if [ "$raw" -gt 100 ] && [ "$raw" -lt 1500 ] 2>/dev/null; then
                echo "$d"; return
            fi ;;
        esac
    done
    for z in /sys/class/thermal/thermal_zone*/temp; do
        raw=$(cat "$z" 2>/dev/null || echo 0)
        if [ "$raw" -gt 100 ] && [ "$raw" -lt 1500 ] 2>/dev/null; then
            echo "$(dirname "$z")"; return
        fi
    done
    echo "/sys/class/thermal/thermal_zone0"
}

# ── Actions ───────────────────────────────────────────────────────
case "$ACTION" in

    get_token)
        # Bootstrap endpoint — returns the token so WebUI can store it in memory.
        # Root-only readable token file; only the WebUI (served from root) can fetch this.
        _t=$(cat "$_TOKEN_FILE" 2>/dev/null | tr -d '[:space:]' || echo "")
        if [ -n "$_t" ]; then
            printf '{"ok":true,"token":"%s"}' "$_t"
        else
            printf '{"ok":false,"error":"Token not initialized — reflash module"}\n'
        fi
        ;;

    status)
        LEVEL=$(cat /sys/class/power_supply/battery/capacity 2>/dev/null || echo 0)
        TEMP_RAW=$(cat /sys/class/power_supply/battery/temp 2>/dev/null || echo 280)
        TEMP=$(echo "$TEMP_RAW" | awk '{printf "%.1f",$1/10}')
        STATUS=$(cat /sys/class/power_supply/battery/status 2>/dev/null || echo Unknown)
        VOLTAGE=$(cat /sys/class/power_supply/battery/voltage_now 2>/dev/null \
            | awk '{printf "%d",$1/1000}' || echo 0)
        CURRENT_RAW=$(cat /sys/class/power_supply/battery/current_now 2>/dev/null || echo 0)

        # PATCH-CRITICAL-3: threshold-based unit detection matching service.sh.
        # Original code unconditionally divided by 1000, treating all kernels as µA.
        # On MTK/SDM devices reporting in mA (e.g. raw=2450 for 2.45A), this produced
        # 2mA. Threshold >100000: no charger delivers 100A at the battery power rail,
        # so values above that are always µA. Values <=100000 are already in mA.
        CURRENT=$(echo "$CURRENT_RAW" | awk '{v=($1<0)?-$1:$1; if(v>100000)v=v/1000; printf "%d",v}')

        PROFILE=""
        [ -f "$IOB_DIR/profile" ] && PROFILE=$(cat "$IOB_DIR/profile" 2>/dev/null | tr -d '[:space:]')
        [ -z "$PROFILE" ] && PROFILE=$(cfg_get "profile")
        echo "$PROFILE" | grep -qE '^(eco|balanced|beast|gaming)$' || PROFILE="balanced"

        _CPU_ZONE=$(_detect_cpu_zone_api)
        CPU_TEMP_RAW=$(cat "$_CPU_ZONE/temp" 2>/dev/null || echo 0)
        [ "$CPU_TEMP_RAW" -gt 10000 ] 2>/dev/null \
            && CPU_TEMP_DEC=$((CPU_TEMP_RAW / 100)) || CPU_TEMP_DEC=$CPU_TEMP_RAW
        CPU_TEMP=$(echo "$CPU_TEMP_DEC" | awk '{printf "%.1f",$1/10}')

        # PATCH-PERF-3 + PATCH-MINOR-1:
        # Read from cache file (non-blocking — never stalls the CGI response).
        # Spawn a fresh background sample ONLY if the cache is >= 3 seconds old.
        # Use PID-stamped temp file to prevent two concurrent polls from racing
        # on the same cpu_pct.cache.tmp path.
        CPU_PCT=0
        _cpu_cache="$IOB_DIR/cpu_pct.cache"
        _cpu_ts_file="$IOB_DIR/cpu_pct.cache.ts"
        if [ -f "$_cpu_cache" ]; then
            CPU_PCT=$(cat "$_cpu_cache" 2>/dev/null | tr -cd '0-9.' | head -c 5 || echo 0)
            [ -z "$CPU_PCT" ] && CPU_PCT=0
        fi
        # Spawn background resample only when stale
        if [ -f "$MODDIR/tools/cpu_usage.sh" ]; then
            _now=$(date +%s 2>/dev/null || echo 0)
            _last_ts=$(cat "$_cpu_ts_file" 2>/dev/null || echo 0)
            if [ $(( _now - _last_ts )) -ge 3 ] 2>/dev/null; then
                echo "$_now" > "$_cpu_ts_file" 2>/dev/null
                _cpu_tmp="$IOB_DIR/cpu_pct.cache.tmp.$$"
                (sh "$MODDIR/tools/cpu_usage.sh" > "$_cpu_tmp" 2>/dev/null \
                    && mv "$_cpu_tmp" "$_cpu_cache" 2>/dev/null \
                    || rm -f "$_cpu_tmp" 2>/dev/null) &
            fi
        fi

        # V5-P2: Battery health telemetry
        CHARGE_FULL_MAH=$(cat /sys/class/power_supply/battery/charge_full 2>/dev/null \
            | awk '{printf "%d",$1/1000}' || echo 0)
        CHARGE_FULL_DESIGN=$(cat /sys/class/power_supply/battery/charge_full_design 2>/dev/null \
            | awk '{printf "%d",$1/1000}' || echo 0)
        BATT_HEALTH_PCT=100
        [ "$CHARGE_FULL_DESIGN" -gt 0 ] 2>/dev/null && \
            BATT_HEALTH_PCT=$(awk -v f="$CHARGE_FULL_MAH" -v d="$CHARGE_FULL_DESIGN" \
                'BEGIN{printf "%d",(f/d)*100}' 2>/dev/null || echo 100)
        BATT_HEALTH_WARNING="ok"
        [ "$BATT_HEALTH_PCT" -lt 80 ] 2>/dev/null && BATT_HEALTH_WARNING="warn"
        [ "$BATT_HEALTH_PCT" -lt 70 ] 2>/dev/null && BATT_HEALTH_WARNING="severe"

        printf '{"ok":true,"level":%s,"temp":%s,"cpu_temp":%s,"status":"%s","voltage":%s,"current":%s,"profile":"%s","cpu":%s,"batt_health_pct":%s,"batt_health_warning":"%s","charge_full_mah":%s}\n' \
            "$LEVEL" "$TEMP" "$CPU_TEMP" "$STATUS" "$VOLTAGE" "$CURRENT" "$PROFILE" "$CPU_PCT" \
            "$BATT_HEALTH_PCT" "$BATT_HEALTH_WARNING" "$CHARGE_FULL_MAH"
        ;;

    logs)
        if [ -f "$LOG" ]; then
            LINES=$(tail -120 "$LOG" 2>/dev/null \
                | awk '{gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); printf "%s\\n",$0}')
            printf '{"ok":true,"output":"%s"}\n' "$LINES"
        else
            echo '{"ok":false,"error":"log not found"}'
        fi
        ;;

    whitelist_list)
        if [ -f "$WHITELIST" ]; then
            OUT=$(grep -v '^#\|^[[:space:]]*$' "$WHITELIST" 2>/dev/null | tr '\n' '|')
            printf '{"ok":true,"output":"%s"}\n' "$OUT"
        else
            echo '{"ok":true,"output":""}'
        fi
        ;;

    whitelist_add)
        PKG=$(printf '%s' "$PARAM" | tr -cd 'a-zA-Z0-9._-')
        if valid_pkg "$PKG"; then
            touch "$WHITELIST" 2>/dev/null; chmod 644 "$WHITELIST" 2>/dev/null
            if ! grep -qxF "$PKG" "$WHITELIST" 2>/dev/null; then
                echo "$PKG" >> "$WHITELIST"
                printf '{"ok":true,"added":"%s"}\n' "$PKG"
            else
                printf '{"ok":true,"note":"already whitelisted","pkg":"%s"}\n' "$PKG"
            fi
        else
            echo '{"ok":false,"error":"invalid package name"}'
        fi
        ;;

    whitelist_remove)
        PKG=$(printf '%s' "$PARAM" | tr -cd 'a-zA-Z0-9._-')
        if valid_pkg "$PKG"; then
            if [ -f "$WHITELIST" ] && grep -qxF "$PKG" "$WHITELIST" 2>/dev/null; then
                tmp="$WHITELIST.tmp.$$"
                grep -vxF "$PKG" "$WHITELIST" > "$tmp" 2>/dev/null && \
                    mv "$tmp" "$WHITELIST" || rm -f "$tmp"
                chmod 644 "$WHITELIST" 2>/dev/null
                printf '{"ok":true,"removed":"%s"}\n' "$PKG"
            else
                echo '{"ok":false,"error":"package not in whitelist"}'
            fi
        else
            echo '{"ok":false,"error":"invalid package name"}'
        fi
        ;;

    running_apps)
        APPS=$(dumpsys activity processes 2>/dev/null \
            | awk '/^ *app=ProcessRecord.*uid=[1-9][0-9][0-9][0-9][0-9]/{
                if (match($0, /processName=[^ }]+/)) {
                    pkg = substr($0, RSTART+12, RLENGTH-12)
                    if (pkg != "") print pkg
                }
            }' | sort -u 2>/dev/null | tr '\n' '|') || APPS=""
        if [ -z "$APPS" ]; then
            APPS=$(ps -A -o USER,NAME 2>/dev/null \
                | awk '$1~/^u[0-9]/{print $2}' \
                | grep '\.' | grep -v '^[0-9]' | sort -u | tr '\n' '|') || APPS=""
        fi
        printf '{"ok":true,"output":"%s"}\n' "$APPS"
        ;;

    read_syslog)
        if [ -f "$LOG" ]; then
            OUT=$(tail -120 "$LOG" 2>/dev/null | tr '\n' '|')
            printf '{"ok":true,"output":"%s"}\n' "$OUT"
        else
            echo '{"ok":true,"output":""}'
        fi
        ;;

    kill_bg)
        touch "$IOB_DIR/kill_bg.trigger" 2>/dev/null
        chmod 600 "$IOB_DIR/kill_bg.trigger" 2>/dev/null
        echo '{"ok":true,"note":"kill queued — service will process with whitelist and thermal checks"}'
        ;;

    set_profile)
        echo "$PARAM" | grep -qE '^(eco|balanced|beast|gaming)$' && {
            echo "$PARAM" > "$IOB_DIR/profile"
            chmod 664 "$IOB_DIR/profile" 2>/dev/null
            cfg_set "profile" "$PARAM"
            cfg_set "user_override" "1"
            INFO="$MODDIR/webroot/battery_info.prop"
            if [ -f "$INFO" ]; then
                tmp="$INFO.tmp.$$"
                grep -v "^profile=\|^user_override=" "$INFO" > "$tmp" 2>/dev/null || true
                { echo "profile=$PARAM"; echo "user_override=1"; } >> "$tmp"
                mv "$tmp" "$INFO" 2>/dev/null || rm -f "$tmp" 2>/dev/null
            fi
            echo '{"ok":true}'
        } || echo '{"ok":false,"error":"invalid profile"}'
        ;;

    get_config)
        P=""
        [ -f "$IOB_DIR/profile" ] && P=$(cat "$IOB_DIR/profile" 2>/dev/null | tr -d '[:space:]')
        [ -z "$P" ] && P=$(cfg_get "profile")
        echo "$P" | grep -qE '^(eco|balanced|beast|gaming)$' || P="balanced"
        OUT="profile=$P|"
        [ -f "$CONFIG" ] && OUT="$OUT$(grep -v "^#\|^[[:space:]]*$\|^profile=" \
            "$CONFIG" 2>/dev/null | tr '\n' '|')"
        SAFE=$(printf '%s' "$OUT" | awk '{gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); printf "%s",$0}')
        printf '{"ok":true,"output":"%s"}\n' "$SAFE"
        ;;

    save_cfg|write_config)
        RAW=$(printf '%s' "$PARAM" | sed 's/%22/"/g;s/%7B/{/g;s/%7D/}/g;s/%3A/:/g;s/%2C/,/g;s/+/ /g')
        KEY=$(echo "$RAW" | sed -n 's/.*"key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        VAL=$(echo "$RAW" | sed -n 's/.*"val"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        [ -z "$KEY" ] && KEY=$(echo "$PARAM" | cut -d= -f1)
        [ -z "$VAL" ] && VAL=$(echo "$PARAM" | cut -d= -f2-)
        VAL=$(printf '%s' "$VAL" | tr -d '\n\r\000')
        echo "$KEY" | grep -qE '^[a-zA-Z0-9_]+$' && {
            cfg_set "$KEY" "$VAL"; echo '{"ok":true}'
        } || echo '{"ok":false,"error":"invalid key"}'
        ;;

    save_glass)
        A=$(echo "$PARAM" | sed -n 's/.*alpha=\([^,&]*\).*/\1/p' | tr -cd '0-9')
        B=$(echo "$PARAM" | sed -n 's/.*blur=\([^,&]*\).*/\1/p'  | tr -cd '0-9')
        O=$(echo "$PARAM" | sed -n 's/.*border=\([^,&]*\).*/\1/p' | tr -cd '0-9')
        [ -z "$A" ] && A=96
        [ -z "$B" ] && B=20
        [ -z "$O" ] && O=8
        A=$(echo "$A" | awk '{v=$1; if(v<0)v=0; if(v>100)v=100; print v}')
        B=$(echo "$B" | awk '{v=$1; if(v<0)v=0; if(v>40)v=40; print v}')
        O=$(echo "$O" | awk '{v=$1; if(v<0)v=0; if(v>20)v=20; print v}')
        printf "alpha=%s\nblur=%s\nborder=%s\n" "$A" "$B" "$O" > "$GLASS_CONF"
        chmod 664 "$GLASS_CONF" 2>/dev/null
        echo '{"ok":true}'
        ;;

    get_glass)
        if [ -f "$GLASS_CONF" ]; then
            OUT=$(cat "$GLASS_CONF" | tr '\n' '|')
            printf '{"ok":true,"output":"%s"}\n' "$OUT"
        else
            echo '{"ok":true,"output":"alpha=96|blur=20|border=8"}'
        fi
        ;;

    list_pkgs)
        if [ -s "$UA" ]; then
            PKGS=$(cat "$UA" | tr '\n' '|')
        elif [ -f /data/system/packages.list ]; then
            PKGS=$(awk '$2>=10000{print $1}' /data/system/packages.list 2>/dev/null \
                | grep '\.' | sort | tr '\n' '|')
        else
            PKGS=$(pm list packages -3 2>/dev/null | sed 's/^package://' | tr '\n' '|')
        fi
        printf '{"ok":true,"output":"%s"}\n' "$PKGS"
        ;;

    list_pkgs_sys)
        if [ -s "$SA" ]; then
            PKGS=$(cat "$SA" | tr '\n' '|')
        elif [ -f /data/system/packages.list ]; then
            PKGS=$(awk '$2<10000{print $1}' /data/system/packages.list 2>/dev/null \
                | grep '\.' | sort | tr '\n' '|')
        else
            PKGS=$(pm list packages -s 2>/dev/null | sed 's/^package://' | tr '\n' '|')
        fi
        printf '{"ok":true,"output":"%s"}\n' "$PKGS"
        ;;

    refresh_pkglist)
        PL=/data/system/packages.list
        if [ -f "$PL" ] && [ -s "$PL" ]; then
            awk '$2>=10000{print $1}' "$PL" 2>/dev/null | grep '\.' | sort > "$UA"
            awk '$2<10000{print $1}'  "$PL" 2>/dev/null | grep '\.' | sort > "$SA"
            chmod 644 "$UA" "$SA" 2>/dev/null
        fi
        [ -s "$UA" ] || pm list packages -3 2>/dev/null | sed 's/^package://' \
            | grep '\.' | sort > "$UA" 2>/dev/null
        [ -s "$SA" ] || pm list packages -s 2>/dev/null | sed 's/^package://' \
            | grep '\.' | sort > "$SA" 2>/dev/null
        chmod 644 "$UA" "$SA" 2>/dev/null
        COUNT=$(wc -l < "$UA" 2>/dev/null | tr -d ' ' || echo 0)
        printf '{"ok":true,"count":%s}\n' "$COUNT"
        ;;

    set_gms_doze)
        # V5-REMOVED: GMS doze appops writes deleted from api.sh.
        # On Android 12+ GMS holds a SYSTEM_SERVICE exemption — silently no-op.
        # On Android 11 it breaks FCM push, Google Pay, Find My Device, 2FA apps.
        # Config key write kept so existing config files don't break, but no action.
        echo "$PARAM" | grep -qE '^[01]$' && {
            cfg_set "gms_doze" "$PARAM"
            echo '{"ok":true,"note":"gms_doze removed in V5 — no action taken"}'
        } || echo '{"ok":false,"error":"invalid param"}'
        ;;

    set_wifi_boost)
        echo "$PARAM" | grep -qE '^[01]$' && {
            cfg_set "wifi_boost" "$PARAM"
            if [ "$PARAM" = "1" ]; then
                sh "$MODDIR/tools/wifi_boost.sh" boost 2>/dev/null &
            else
                sh "$MODDIR/tools/wifi_boost.sh" reset 2>/dev/null &
            fi
            echo '{"ok":true}'
        } || echo '{"ok":false,"error":"invalid param"}'
        ;;

    set_wifi_bonding_feature)
        FKEY=$(echo "$PARAM" | cut -d= -f1 | tr -cd 'a-zA-Z0-9_')
        FVAL=$(echo "$PARAM" | cut -d= -f2 | tr -cd '01')
        echo "$FKEY" | grep -qE '^(wifi_bonding_engine|wifi_scan_low_mode|wifi_latency_reduce|wifi_net_stability)$' && \
        echo "$FVAL" | grep -qE '^[01]$' && {
            cfg_set "$FKEY" "$FVAL"
            printf '{"ok":true,"feature":"%s","state":%s}\n' "$FKEY" "$FVAL"
        } || echo '{"ok":false,"error":"invalid feature or value"}'
        ;;

    get_wifi_bonding_status)
        printf '{"ok":true,"wifi_boost":"%s","wifi_bonding_engine":"%s","wifi_scan_low_mode":"%s","wifi_latency_reduce":"%s","wifi_net_stability":"%s","compat_wifi_bonding":"%s"}\n' \
            "$(cfg_get wifi_boost)" \
            "$(cfg_get wifi_bonding_engine)" \
            "$(cfg_get wifi_scan_low_mode)" \
            "$(cfg_get wifi_latency_reduce)" \
            "$(cfg_get wifi_net_stability)" \
            "$([ -d /data/adb/modules/wifi-bonding ] && echo 1 || echo 0)"
        ;;

    wifi_status)
        OUT=$(sh "$MODDIR/tools/wifi_boost.sh" status 2>/dev/null | tr '\n' '|')
        printf '{"ok":true,"output":"%s"}\n' "$OUT"
        ;;

    read_opt)
        [ -f "$OPT" ] && OUT=$(cat "$OPT" | tr '\n' '|') || OUT=""
        printf '{"ok":true,"output":"%s"}\n' "$OUT"
        ;;

    save_app_mode|set_app_opt)
        PKG=$(echo "$PARAM" | cut -d: -f1)
        MODE=$(echo "$PARAM" | cut -d: -f2)
        if ! valid_pkg "$PKG"; then
            echo '{"ok":false,"error":"invalid package name"}'
            break
        fi
        tmp="$OPT.tmp.$$"
        touch "$OPT" 2>/dev/null; chmod 664 "$OPT" 2>/dev/null
        grep -v "^${PKG}=" "$OPT" 2>/dev/null > "$tmp" || true
        [ "$MODE" != "none" ] && echo "${PKG}=${MODE}" >> "$tmp"
        mv "$tmp" "$OPT" 2>/dev/null || rm -f "$tmp"
        chmod 664 "$OPT" 2>/dev/null
        echo '{"ok":true}'
        ;;

    force_doze)
        dumpsys deviceidle force-idle 2>/dev/null
        echo '{"ok":true}'
        ;;

    emergency_cooldown)
        TOTAL_CORES=0
        for d in /sys/devices/system/cpu/cpu[0-9]*; do
            [ -d "$d" ] && TOTAL_CORES=$((TOTAL_CORES + 1))
        done
        [ "$TOTAL_CORES" -eq 0 ] && TOTAL_CORES=8
        HALF=$((TOTAL_CORES / 2))
        [ "$HALF" -lt 1 ] && HALF=1
        i=$HALF
        while [ "$i" -lt "$TOTAL_CORES" ]; do
            echo 0 > /sys/devices/system/cpu/cpu${i}/online 2>/dev/null || true
            i=$((i + 1))
        done
        settings put global low_power 1 2>/dev/null
        su -lp 2000 -c "cmd notification post -S bigtext \
            -t 'ioBattery — Makima' 'IOB_COOLDOWN' \
            'Device is cooling down. Rest for 2 minutes, darling. Big cores will return.'" \
            2>/dev/null || true
        echo "cooldown_active=1" > "$IOB_DIR/cooldown.prop" 2>/dev/null
        (
            sleep 120
            j=$HALF
            while [ "$j" -lt "$TOTAL_CORES" ]; do
                echo 1 > /sys/devices/system/cpu/cpu${j}/online 2>/dev/null || true
                j=$((j + 1))
            done
            settings put global low_power 0 2>/dev/null
            rm -f "$IOB_DIR/cooldown.prop" 2>/dev/null
            su -lp 2000 -c "cmd notification post -S bigtext \
                -t 'ioBattery — Makima' 'IOB_COOLDOWN' \
                'Cooldown complete. All cores restored. Welcome back, darling.'" \
                2>/dev/null || true
        ) &
        echo '{"ok":true}'
        ;;

    makima_notif)
        echo "$PARAM" | grep -qE '^[01]$' && {
            cfg_set "makima_notif" "$PARAM"
            echo '{"ok":true}'
        } || echo '{"ok":false,"error":"invalid param"}'
        ;;

    compat_status)
        AZENITH=$([ -d /data/adb/modules/AZenith    ] && [ ! -f /data/adb/modules/AZenith/remove    ] && echo 1 || echo 0)
        ENCORE=$([ -d /data/adb/modules/encore      ] && [ ! -f /data/adb/modules/encore/remove      ] && echo 1 || echo 0)
        RACO=$([ -d /data/adb/modules/ProjectRaco   ] && [ ! -f /data/adb/modules/ProjectRaco/remove  ] && echo 1 || echo 0)
        RAIRIN=$([ -d /data/adb/modules/RaiRin-AI   ] && [ ! -f /data/adb/modules/RaiRin-AI/remove    ] && echo 1 || echo 0)
        printf '{"ok":true,"azenith":%s,"encore":%s,"raco":%s,"rairin":%s}\n' \
            "$AZENITH" "$ENCORE" "$RACO" "$RAIRIN"
        ;;

    *) echo '{"ok":false,"error":"unknown action"}' ;;
esac
