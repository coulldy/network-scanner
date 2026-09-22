#!/bin/bash
C='\033[0;36m'
G='\033[0;32m'
Y='\033[1;33m'
N='\033[0m'

while true; do
    IP=$(hostname -I | awk '{print $1}')
    TEMP=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
    TEMP_C=$(echo "scale=1; $TEMP/1000" | bc 2>/dev/null || echo "?")
    RAM=$(free -m | awk '/Mem:/ {print $3"/"$2" MB"}')
    U=$(whoami)

    {
        printf "\033[H\033[2J"
        printf "\n"
        printf "${C}  ◆ SCANNER v1.0${N}  ${Y}— автономный аудит${N}\n"
        printf "\n"
        printf "  ${G}IP${N}    ${Y}%s${N}\n" "$IP"
        printf "  ${G}CPU${N}   ${Y}%s°C${N}\n" "$TEMP_C"
        printf "  ${G}RAM${N}   ${Y}%s${N}\n" "$RAM"
        printf "  ${G}USER${N}  ${Y}%s${N}\n" "$U"
        printf "\n"
        printf "  ${C}→${N}  ${Y}http://%s:8080${N}\n" "$IP"
        printf "\n"
    } > /dev/tty1 2>/dev/null

    sleep 5
done
