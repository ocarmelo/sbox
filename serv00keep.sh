#!/bin/bash
# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"$snb
purple="\e[1;35m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }
export LC_ALL=C
export ${UUID:-''}  
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}   
export ARGO_AUTH=${ARGO_AUTH:-''}     
export vless_port=${vless_port:-''}    
export vmess_port=${vmess_port:-''}  
export hy2_port=${hy2_port:-''}       
export IP=${IP:-''}                  
export reym=${reym:-''}
export reset=${reset:-''}
export resport=${resport:-''}

devil binexec on >/dev/null 2>&1
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
HOSTNAME=$(hostname)
snb=$(hostname | awk -F '.' '{print $1}')

green "客户端使用的IP地址：$IP"

snbok=$(hostname | awk -F '.' '{print $1}')
snb=$USERNAME


nb=$(hostname | cut -d '.' -f 1 | tr -d 's')
if [[ "$reset" =~ ^[Yy]$ ]]; then

bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
devil www del ${USERNAME}.serv00.net > /dev/null 2>&1
sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' "${HOME}/.bashrc" >/dev/null 2>&1
source "${HOME}/.bashrc" >/dev/null 2>&1
find ~ -type f -exec chmod 644 {} \; 2>/dev/null
find ~ -type d -exec chmod 755 {} \; 2>/dev/null
find ~ -type f -exec rm -f {} \; 2>/dev/null
find ~ -type d -empty -exec rmdir {} \; 2>/dev/null
find ~ -exec rm -rf {} \; 2>/dev/null
echo "重置系统完成"
fi
sleep 2
devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"
WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs"
[ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
[ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")

read_ip(){
ym=("$HOSTNAME" "cache$nb.serv00.com" "web$nb.serv00.com")
rm -rf ip.txt
for host in "${ym[@]}"; do
response=$(curl -sL --connect-timeout 5 --max-time 7 "https://ss.fkj.pp.ua/api/getip?host=$host")
if [[ "$response" =~ (unknown|not|error) ]]; then
dig @8.8.8.8 +time=5 +short $host | sort -u >> ip.txt
sleep 1  
else
while IFS='|' read -r ip status; do
if [[ $status == "Accessible" ]]; then
echo "$ip: 可用" >> ip.txt
else
echo "$ip: 被墙" >> ip.txt
fi	
done <<< "$response"
fi
done
if [[ ! "$response" =~ (unknown|not|error) ]]; then
grep ':' $WORKDIR/ip.txt | sort -u -o $WORKDIR/ip.txt
fi
if [[ -z "$IP" ]]; then
IP=$(grep -m 1 "可用" ip.txt | awk -F ':' '{print $1}')
if [ -z "$IP" ]; then
IP=$(okip)
if [ -z "$IP" ]; then
IP=$(head -n 1 ip.txt | awk -F ':' '{print $1}')
fi
fi
fi
}

okip(){
    IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))
    API_URL="https://status.eooce.com/api"
    IP=""
    THIRD_IP=${IP_LIST[2]}
    RESPONSE=$(curl -s --max-time 2 "${API_URL}/${THIRD_IP}")
    if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
        IP=$THIRD_IP
    else
        FIRST_IP=${IP_LIST[0]}
        RESPONSE=$(curl -s --max-time 2 "${API_URL}/${FIRST_IP}")
        
        if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
            IP=$FIRST_IP
        else
            IP=${IP_LIST[1]}
        fi
    fi
    echo "$IP"
    }

uuidport(){
if [[ -z "$UUID" ]]; then
if [ ! -e UUID.txt ]; then
UUID=$(uuidgen -r)

UUID=ada2a6ff-3a5b-4399-8399-44f4520b3903
echo "$UUID" > UUID.txt
else
UUID=$(<UUID.txt)
fi
fi
if [[ -z "$reym" ]]; then
reym=$USERNAME.serv00.net
fi
if [[ -z "$vless_port" ]] || [[ -z "$vmess_port" ]] || [[ -z "$hy2_port" ]]; then
check_port
fi
}

check_port(){
port_list=$(devil port list)
tcp_ports=$(echo "$port_list" | grep -c "tcp")
udp_ports=$(echo "$port_list" | grep -c "udp")

if [[ $tcp_ports -ne 1 || $udp_ports -ne 1 ]]; then
    echo "端口数量不符合要求，正在调整..."

    if [[ $tcp_ports -gt 2 ]]; then
        tcp_to_delete=$((tcp_ports - 2))
        echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
            devil port del $type $port
            echo "已删除TCP端口: $port"
        done
    fi

    if [[ $udp_ports -gt 1 ]]; then
        udp_to_delete=$((udp_ports - 1))
        echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
            devil port del $type $port
            echo "已删除UDP端口: $port"
        done
    fi

    if [[ $tcp_ports -lt 1 ]]; then
        while true; do
            tcp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add tcp $tcp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                echo "已添加TCP端口: $tcp_port"
                break
            else
                echo "端口 $tcp_port 不可用，尝试其他端口..."
            fi
        done
    fi

    if [[ $udp_ports -lt 1 ]]; then
        while true; do
            udp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add udp $udp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                echo "已添加UDP端口: $udp_port"
                break
            else
                echo "端口 $udp_port 不可用，尝试其他端口..."
            fi
        done
    fi
    #echo "端口已调整完成,将断开ssh连接"
    sleep 3
    #devil binexec on >/dev/null 2>&1
    #kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
else
    tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
    tcp_port=$(echo "$tcp_ports" | sed -n '1p')
    udp_port=$(echo "$port_list" | awk '/udp/ {print $1}')

    echo "你的vless-reality的TCP端口: $tcp_port" 
    echo "你的hysteria2的UDP端口: $udp_port"
fi
export vless_port=$tcp_port
export hy2_port=$udp_port
}

download_and_run_singbox() {
if [ ! -s sb.txt ] && [ ! -s ag.txt ]; then
DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
FILE_INFO=("https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/sb web" "https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/server bot")
declare -A FILE_MAP
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

download_with_fallback() {
    local URL=$1
    local NEW_FILENAME=$2

    curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL" &
    CURL_PID=$!
    CURL_START_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    sleep 1
    CURL_CURRENT_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    if [ "$CURL_CURRENT_SIZE" -le "$CURL_START_SIZE" ]; then
        kill $CURL_PID 2>/dev/null
        wait $CURL_PID 2>/dev/null
        wget -q -O "$NEW_FILENAME" "$URL"
        echo -e "\e[1;32mDownloading $NEW_FILENAME by wget\e[0m"
    else
        wait $CURL_PID
        echo -e "\e[1;32mDownloading $NEW_FILENAME by curl\e[0m"
    fi
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
    
    if [ -e "$NEW_FILENAME" ]; then
        echo -e "\e[1;32m$NEW_FILENAME already exists, Skipping download\e[0m"
    else
        download_with_fallback "$URL" "$NEW_FILENAME"
    fi
    
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
done
wait
fi

if [ ! -e private_key.txt ]; then
output=$(./"$(basename ${FILE_MAP[web]})" generate reality-keypair)
private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
echo "${private_key}" > private_key.txt
echo "${public_key}" > public_key.txt
fi
private_key=$(<private_key.txt)
public_key=$(<public_key.txt)
openssl ecparam -genkey -name prime256v1 -out "private.key"
openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"
  cat > config.json << EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
    "inbounds": [
    {
       "tag": "hysteria-in1",
       "type": "hysteria2",
       "listen": "$(dig @8.8.8.8 +time=5 +short "web$nb.serv00.com" | sort -u)",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://www.bing.com",
     "ignore_client_bandwidth":false,
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
        {
       "tag": "hysteria-in2",
       "type": "hysteria2",
       "listen": "$(dig @8.8.8.8 +time=5 +short "$HOSTNAME" | sort -u)",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://www.bing.com",
     "ignore_client_bandwidth":false,
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
        {
       "tag": "hysteria-in3",
       "type": "hysteria2",
       "listen": "$(dig @8.8.8.8 +time=5 +short "cache$nb.serv00.com" | sort -u)",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://www.bing.com",
     "ignore_client_bandwidth":false,
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
    {
        "tag": "vless-reality-vesion",
        "type": "vless",
        "listen": "::",
        "listen_port": $vless_port,
        "users": [
            {
              "uuid": "$UUID",
              "flow": "xtls-rprx-vision"
            }
        ],
        "tls": {
            "enabled": true,
            "server_name": "$reym",
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": "$reym",
                    "server_port": 443
                },
                "private_key": "$private_key",
                "short_id": [
                  ""
                ]
            }
        }
    }
 ],
     "outbounds": [
     {
        "type": "wireguard",
        "tag": "wg",
        "server": "162.159.192.200",
        "server_port": 4500,
        "local_address": [
                "172.16.0.2/32",
                "2606:4700:110:8f77:1ca9:f086:846c:5f9e/128"
        ],
        "private_key": "wIxszdR2nMdA7a2Ul3XQcniSfSZqdqjPb6w6opvf5AU=",
        "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "reserved": [
            126,
            246,
            173
        ]
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
   "route": {
       "rule_set": [
      {
        "tag": "google-gemini",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google-gemini.srs",
        "download_detour": "direct"
      }
    ],
EOF
if [[ "$nb" =~ (14|15|16) ]]; then
cat >> config.json <<EOF 
    "rules": [
    {
     "domain": [
     "jnn-pa.googleapis.com"
      ],
     "outbound": "wg"
     },
     {
     "rule_set":[
     "google-gemini"
     ],
     "outbound": "wg"
    }
    ],
    "final": "direct"
    }  
}
EOF
else
  cat >> config.json <<EOF
    "final": "direct"
    }  
}
EOF
fi

if ! ps aux | grep '[r]un -c con' > /dev/null; then
ps aux | grep '[r]un -c con' | awk '{print $2}' | xargs -r kill -9 > /dev/null 2>&1
if [ -e "$(basename "${FILE_MAP[web]}")" ]; then
   echo "$(basename "${FILE_MAP[web]}")" > sb.txt
   sbb=$(cat sb.txt)   
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 5
if pgrep -x "$sbb" > /dev/null; then
    green "$sbb 主进程已启动"
else
    red "$sbb 主进程未启动, 重启中..."
    pkill -x "$sbb"
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 2
    purple "$sbb 主进程已重启"
fi
else
    sbb=$(cat sb.txt)   
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 5
if pgrep -x "$sbb" > /dev/null; then
    green "$sbb 主进程已启动"
    # hugua 20250311
    green "当前使用IP：$IP" 
else
    red "$sbb 主进程未启动, 重启中..."
    pkill -x "$sbb"
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 2
    purple "$sbb 主进程已重启"
fi
fi
else
green "主进程已启动"
# hugua 20250311
green "当前使用IP：$IP"
fi


get_links(){
argodomain=$(get_argodomain)
echo -e "\e[1;32mArgo域名：\e[1;35m${argodomain}\e[0m\n"
#hugua 20250312 v2rayN
vl_link="vless://$UUID@$IP:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reym&fp=chrome&pbk=$public_key&type=tcp&headerType=none#PL-$snb-reality"

hy2_link="hysteria2://$UUID@$IP:$hy2_port?sni=www.bing.com&alpn=h3&insecure=1#PL-$snb-hy2"
echo "$hy2_link" >> jh.txt
baseurl=$(base64 -w 0 < jh.txt)

cat > sing_box.json <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "",
      "external_ui_download_detour": "",
      "secret": "",
      "default_mode": "Rule"
       },
      "cache_file": {
            "enabled": true,
            "path": "cache.db",
            "store_fakeip": true
        }
    },
    "dns": {
        "servers": [
            {
                "tag": "proxydns",
                "address": "tls://8.8.8.8/dns-query",
                "detour": "select"
            },
            {
                "tag": "localdns",
                "address": "h3://223.5.5.5/dns-query",
                "detour": "direct"
            },
            {
                "tag": "dns_fakeip",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "localdns",
                "disable_cache": true
            },
            {
                "clash_mode": "Global",
                "server": "proxydns"
            },
            {
                "clash_mode": "Direct",
                "server": "localdns"
            },
            {
                "rule_set": "geosite-cn",
                "server": "localdns"
            },
            {
                 "rule_set": "geosite-geolocation-!cn",
                 "server": "proxydns"
            },
             {
                "rule_set": "geosite-geolocation-!cn",         
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "dns_fakeip"
            }
          ],
           "fakeip": {
           "enabled": true,
           "inet4_range": "198.18.0.0/15",
           "inet6_range": "fc00::/18"
         },
          "independent_cache": true,
          "final": "proxydns"
        },
      "inbounds": [
    {
      "type": "tun",
           "tag": "tun-in",
	  "address": [
      "172.19.0.1/30",
	  "fd00::1/126"
      ],
      "auto_route": true,
      "strict_route": true,
      "sniff": true,
      "sniff_override_destination": true,
      "domain_strategy": "prefer_ipv4"
    }
  ],
  "outbounds": [
    {
      "tag": "select",
      "type": "selector",
      "default": "auto",
      "outbounds": [
        "auto",
        "vless-$snb",
        "hy2-$snb"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-$snb",
      "server": "$IP",
      "server_port": $vless_port,
      "uuid": "$UUID",
      "packet_encoding": "xudp",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "$reym",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
      "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": ""
        }
      }
    },
    {
        "type": "hysteria2",
        "tag": "hy2-$snb",
        "server": "$IP",
        "server_port": $hy2_port,
        "password": "$UUID",
        "tls": {
            "enabled": true,
            "server_name": "www.bing.com",
            "insecure": true,
            "alpn": [
                "h3"
            ]
        }
    },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "vless-$snb",
        "hy2-$snb"
      ],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    }
  ],
  "route": {
      "rule_set": [
            {
                "tag": "geosite-geolocation-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            }
        ],
    "auto_detect_interface": true,
    "final": "select",
    "rules": [
      {
      "inbound": "tun-in",
      "action": "sniff"
      },
      {
      "protocol": "dns",
      "action": "hijack-dns"
      },
      {
      "port": 443,
      "network": "udp",
      "action": "reject"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "outbound": "select"
      },
      {
        "rule_set": "geoip-cn",
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-cn",
        "outbound": "direct"
      },
      {
      "ip_is_private": true,
      "outbound": "direct"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "outbound": "select"
      }
    ]
  },
    "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}
EOF

cat > clash_meta.yaml <<EOF
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:

- name: vless-reality-vision-               
  type: vless
  server: $IP                           
  port: $vless_port                                
  uuid: $UUID   
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: $reym                 
  reality-opts: 
    public-key: $public_key                      
  client-fingerprint: chrome                  

- name: hysteria2-                            
  type: hysteria2                                      
  server: $IP                               
  port: $hy2_port                                
  password: $UUID                          
  alpn:
    - h3
  sni: www.bing.com                               
  skip-cert-verify: true
  fast-open: true

proxy-groups:
- name: Balance
  type: load-balance
  url: https://www.gstatic.com/generate_204
  interval: 300
  strategy: round-robin
  proxies:
    - vless-reality-vision-                              
    - hysteria2-

- name: Auto
  type: url-test
  url: https://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - vless-reality-vision-                             
    - hysteria2-
    
- name: Select
  type: select
  proxies:
    - Balance                                         
    - Auto
    - DIRECT
    - vless-reality-vision-                              
    - hysteria2-
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Select
  
EOF

rm -rf ${FILE_PATH}/*.txt
v2sub=$(cat jh.txt)
echo "$v2sub" > ${FILE_PATH}/${UUID}_v2sub.txt
cat clash_meta.yaml > ${FILE_PATH}/${UUID}_clashmeta.txt
cat sing_box.json > ${FILE_PATH}/${UUID}_singbox.txt
curl -sL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/index.html -o "$FILE_PATH"/index.html
V2rayN_LINK="https://${USERNAME}.serv00.net/${UUID}_v2sub.txt"
Clashmeta_LINK="https://${USERNAME}.serv00.net/${UUID}_clashmeta.txt"
Singbox_LINK="https://${USERNAME}.serv00.net/${UUID}_singbox.txt"
cat > list.txt <<EOF
=================================================================================================

当前客户端正在使用的IP：$IP
如默认节点IP被墙，可在客户端地址更换以下其他IP
$(dig @8.8.8.8 +time=5 +short "web$nb.serv00.com" | sort -u)
$(dig @8.8.8.8 +time=5 +short "$HOSTNAME" | sort -u)
$(dig @8.8.8.8 +time=5 +short "cache$nb.serv00.com" | sort -u)
-------------------------------------------------------------------------------------------------

一、Vless-reality分享链接如下：
$vl_link
-------------------------------------------------------------------------------------------------

二、HY2分享链接如下：
$hy2_link
-------------------------------------------------------------------------------------------------

三、以上节点的聚合通用订阅分享链接如下：
$V2rayN_LINK

以上节点聚合通用分享码：
$baseurl
-------------------------------------------------------------------------------------------------

四、查看Sing-box与Clash-meta的订阅配置文件，请进入主菜单选择4

Clash-meta订阅分享链接：
$Clashmeta_LINK

Sing-box订阅分享链接：
$Singbox_LINK
-------------------------------------------------------------------------------------------------

=================================================================================================

EOF
cat list.txt
sleep 2
rm -rf sb.log core tunnel.yml tunnel.json fake_useragent_0.2.0.json
}

if [[ "$resport" =~ ^[Yy]$ ]]; then
portlist=$(devil port list | grep -E '^[0-9]+[[:space:]]+[a-zA-Z]+' | sed 's/^[[:space:]]*//')
if [[ -z "$portlist" ]]; then
yellow "无端口"
else
while read -r line; do
port=$(echo "$line" | awk '{print $1}')
port_type=$(echo "$line" | awk '{print $2}')
yellow "删除端口 $port ($port_type)"
devil port del "$port_type" "$port"
done <<< "$portlist"
fi
check_port
fi
# hugua  snb-snbok
rm -rf $HOME/domains/${snbok}.${USERNAME}.serv00.net/logs/*
install_singbox() {
cd $WORKDIR
read_ip
uuidport
download_and_run_singbox
get_links
cd
}
install_singbox
