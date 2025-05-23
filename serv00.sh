#!/bin/bash
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
HOSTNAME=$(hostname)
WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs"
snb=$(hostname | awk -F '.' '{print $1}')
snbok=$snb
nb=$(hostname | cut -d '.' -f 1 | tr -d 's')
devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"
keep_path="${HOME}/domains/${snb}.${USERNAME}.serv00.net/public_nodejs"
[ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
[ -d "$keep_path" ] || mkdir -p "$keep_path"
[ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
devil binexec on >/dev/null 2>&1

read_ip() {
cat ip.txt
reading "请输入上面三个IP中的任意一个 (建议默认回车自动选择可用IP): " IP
if [[ -z "$IP" ]]; then
IP=$(grep -m 1 "可用" ip.txt | awk -F ':' '{print $1}')
if [ -z "$IP" ]; then
IP=$(okip)
if [ -z "$IP" ]; then
IP=$(head -n 1 ip.txt | awk -F ':' '{print $1}')
fi
fi
fi
green "你选择的IP为: $IP"
}
read_uuid() {
        reading "请输入统一的uuid密码 (建议回车默认随机): " UUID
        if [[ -z "$UUID" ]]; then
	   UUID=$(uuidgen -r)
           UUID=ada2a6ff-3a5b-4399-8399-44f4520b3903
        fi
	green "你的uuid为: $UUID"
}
read_reym() {
	yellow "方式一：(推荐)使用Serv00自带域名，不支持proxyip功能：输入回车"
        yellow "方式二：支持其他域名，注意要符合reality域名规则：输入域名"
        reading "请输入reality域名 【请选择 回车 或者 输入域名】: " reym
        if [[ -z "$reym" ]]; then
	    reym=$USERNAME.serv00.net
        fi
	green "你的reality域名为: $reym"
}
resallport(){
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
if [[ -e $WORKDIR/config.json ]]; then
hyp=$(jq -r '.inbounds[0].listen_port' $WORKDIR/config.json)
purple "检测到Serv00脚本已安装，执行端口替换，请稍等……"
sed -i '' "12s/$hyp/$hy2_port/g" $WORKDIR/config.json
sed -i '' "33s/$hyp/$hy2_port/g" $WORKDIR/config.json
sed -i '' "54s/$hyp/$hy2_port/g" $WORKDIR/config.json
sed -i '' -e "19s|'$hyp'|'$hy2_port'|" serv00keep.sh
bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
sleep 1
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
sleep 5
green "端口替换完成！"
ps aux | grep '[r]un -c con' > /dev/null && green "主进程启动成功，单节点用户修改下客户端协议端口，订阅链接用户更新下订阅即可" || yellow "Sing-box主进程启动失败，再次重置端口或者多刷几次保活网页，可能会自动恢复"
fi
}
check_port () {
port_list=$(devil port list)
tcp_ports=$(echo "$port_list" | grep -c "tcp")
udp_ports=$(echo "$port_list" | grep -c "udp")
if [[ $tcp_ports -ne 1 || $udp_ports -ne 1 ]]; then
    red "端口数量不符合要求，正在调整..."

    if [[ $tcp_ports -gt 1 ]]; then
        tcp_to_delete=$((tcp_ports - 1))
        echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
            devil port del $type $port
            green "已删除TCP端口: $port"
        done
    fi

    if [[ $udp_ports -gt 1 ]]; then
        udp_to_delete=$((udp_ports - 1))
        echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
            devil port del $type $port
            green "已删除UDP端口: $port"
        done
    fi
   
    if [[ $tcp_ports -lt 1 ]]; then
        while true; do
            tcp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add tcp $tcp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "已添加TCP端口: $tcp_port"
                break
            else
                yellow "端口 $tcp_port 不可用，尝试其他端口..."
            fi
        done
    fi

    if [[ $udp_ports -lt 1 ]]; then
        while true; do
            udp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add udp $udp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "已添加UDP端口: $udp_port"
                break
            else
                yellow "端口 $udp_port 不可用，尝试其他端口..."
            fi
        done
    fi
    green "端口已调整完成,将断开ssh连接,请重新连接shh重新执行脚本"
    devil binexec on >/dev/null 2>&1
    kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
    sleep 3
else
    tcp_port=$(echo "$port_list" | awk '/tcp/ {print $1}' | sed -n '1p')
    udp_port=$(echo "$port_list" | awk '/udp/ {print $1}')
    purple "当前TCP端口: $tcp_port"
    purple "当前UDP端口: $udp_port"
fi
export vless_port=$tcp_port
export hy2_port=$udp_port
green "你的vless-reality端口: $vless_port"
green "你的hysteria2端口: $hy2_port"
}

install_singbox() {
if [[ -e $WORKDIR/list.txt ]]; then
yellow "已安装sing-box，请先选择2卸载，再执行安装" && exit
fi
sleep 2
        cd $WORKDIR
	echo
	    read_ip
 	echo
        read_reym
	echo
	    read_uuid
        echo
        check_port
	echo
        sleep 2
        download_and_run_singbox
	cd
        fastrun
	green "创建快捷方式：sb"
	echo
	    servkeep
        cd $WORKDIR
        echo
        get_links
	cd
        purple "************************************************************"
        purple "Serv00脚本安装结束！再次进入脚本时，请输入快捷方式：sb"
	purple "************************************************************"
}

uninstall_singbox() {
  reading "\n确定要卸载吗？【y/n】: " choice
    case "$choice" in
       [Yy])
	  bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
	        rm -rf $WORKDIR && find ${FILE_PATH} -mindepth 1 ! -name 'index.html' -exec rm -rf {} +
            devil www del ${snb}.${USERNAME}.serv00.net nodejs 2>/dev/null || true
            rm -rf "${HOME}/bin/sb" >/dev/null 2>&1
            [ -d "${HOME}/bin" ] && [ -z "$(ls -A "${HOME}/bin")" ] && rmdir "${HOME}/bin"
            rm -rf serv00keep.sh webport.sh serv00.sh
            rm -rf ${HOME}/domains/${USERNAME}.serv00.net/public_nodejs 2 >/dev/null || true
            sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' "${HOME}/.bashrc" >/dev/null 2>&1
            source "${HOME}/.bashrc"
	    clear
       	    green "Sing-box已完全卸载"
          ;;
        [Nn]) exit 0 ;;
    	  *) red "无效的选择，请输入y或n" && menu ;;
    esac
}


kill_all_tasks() {
reading "\n清理所有进程并清空所有安装内容，将退出ssh连接，确定继续清理吗？【y/n】: " choice
  case "$choice" in
    [Yy]) 
    bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
    devil www del ${snb}.${USERNAME}.serv00.net > /dev/null 2>&1
    devil www del ${USERNAME}.serv00.net > /dev/null 2>&1
    sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' "${HOME}/.bashrc" >/dev/null 2>&1
    source "${HOME}/.bashrc" >/dev/null 2>&1 
    purple "************************************************************"
    purple "Serv00清理重置完成！"
    purple "欢迎继续使用脚本：bash <(curl -Ls https://raw.githubusercontent.com/ocarmelo/sbox/main/serv00.sh)"
    purple "************************************************************"
    find ~ -type f -exec chmod 644 {} \; 2>/dev/null
    find ~ -type d -exec chmod 755 {} \; 2>/dev/null
    find ~ -type f -exec rm -f {} \; 2>/dev/null
    find ~ -type d -empty -exec rmdir {} \; 2>/dev/null
    find ~ -exec rm -rf {} \; 2>/dev/null
    killall -9 -u $(whoami)
    ;;
    *) menu ;;
  esac
}

download_and_run_singbox() {
DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
FILE_INFO=("https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/sb web")
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

output=$(./"$(basename ${FILE_MAP[web]})" generate reality-keypair)
private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

echo "${private_key}" > private_key.txt
echo "${public_key}" > public_key.txt
green "你的reality域名public_key: $public_key="

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

if [ -e "$(basename "${FILE_MAP[web]}")" ]; then
   echo "$(basename "${FILE_MAP[web]}")" > sb.txt
   sbb=$(cat sb.txt)
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 5
if pgrep -x "$sbb" > /dev/null; then
    green "$sbb 主进程已启动"
else
for ((i=1; i<=5; i++)); do
    red "$sbb 主进程未启动, 重启中... (尝试次数: $i)"
    pkill -x "$sbb"
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 5
    if pgrep -x "$sbb" > /dev/null; then
        purple "$sbb 主进程已成功重启"
        break
    fi
    if [[ $i -eq 5 ]]; then
        red "$sbb 主进程重启失败"
    fi
done
fi
fi
}

get_links(){
echo -e "\n"
vl_link="vless://$UUID@$IP:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reym&fp=chrome&pbk=$public_key&type=tcp&headerType=none#PL-$snb-reality"
echo "$vl_link" > jh.txt
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
        "vless-",
        "hy2-"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-",
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
        "tag": "hy2-",
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
        "vless-",
        "hy2-"
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

sleep 2
v2sub=$(cat jh.txt)
echo "$v2sub" > ${FILE_PATH}/${UUID}_v2sub.txt
cat clash_meta.yaml > ${FILE_PATH}/${UUID}_clashmeta.txt
cat sing_box.json > ${FILE_PATH}/${UUID}_singbox.txt
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

showlist(){
if [[ -e $WORKDIR/list.txt ]]; then
green "查看节点、订阅等信息！更新中，请稍等……"
sleep 3
cat $WORKDIR/list.txt
else
red "未安装脚本，请选择1进行安装" && exit
fi
}

showsbclash(){
if [[ -e $WORKDIR/sing_box.json ]]; then
green "查看clash与singbox配置明文！更新中，请稍等……"
sleep 3
green "Sing_box配置文件如下，可上传到订阅类客户端上使用："
sleep 2
cat $WORKDIR/sing_box.json 
echo
echo
green "Clash_meta配置文件如下，可上传到订阅类客户端上使用："
sleep 2
cat $WORKDIR/clash_meta.yaml
echo
else
red "未安装脚本，请选择1进行安装" && exit
fi
}

servkeep() {

green "客户端使用的IP地址：$IP"

sed -i '' -e "14s|''|'$UUID'|" serv00keep.sh
sed -i '' -e "17s|''|'$vless_port'|" serv00keep.sh
sed -i '' -e "19s|''|'$hy2_port'|" serv00keep.sh
sed -i '' -e "20s|''|'$IP'|" serv00keep.sh
sed -i '' -e "21s|''|'$reym'|" serv00keep.sh
echo '#!/bin/bash
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
USERNAME=$(whoami | tr '\''[:upper:]'\'' '\''[:lower:]'\'')
WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs"
snb=$(hostname | awk -F '\''.'\'' '\''{print $1}'\'')
' > webport.sh
declare -f resallport >> webport.sh
declare -f check_port >> webport.sh
echo 'resallport' >> webport.sh
chmod +x webport.sh
green "开始安装多功能主页，请稍等……"
devil www del ${snb}.${USERNAME}.serv00.net > /dev/null 2>&1
devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
devil www add ${snb}.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1
ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
rm -rf $HOME/.npmrc > /dev/null 2>&1
cd "$keep_path"
npm install basic-auth express dotenv axios --silent > /dev/null 2>&1
rm $HOME/domains/${snb}.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
devil www restart ${snb}.${USERNAME}.serv00.net
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
green "安装完毕，多功能主页地址：http://${snb}.${USERNAME}.serv00.net" && sleep 2
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

fastrun(){
if [[ -e $WORKDIR/config.json ]]; then
  COMMAND="sb"
  SCRIPT_PATH="$HOME/bin/$COMMAND"
  mkdir -p "$HOME/bin"
  curl -Ls https://raw.githubusercontent.com/ocarmelo/sbox/main/serv00.sh > "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
      echo "export PATH=\"\$HOME/bin:\$PATH\"" >> "$HOME/.bashrc"
      source "$HOME/.bashrc"
  fi
curl -sL https://raw.githubusercontent.com/ocarmelo/sbox/main/app.js -o "$keep_path"/app.js
sed -i '' "15s/name//g" "$keep_path"/app.js
sed -i '' "60s/key/$UUID/g" "$keep_path"/app.js
sed -i '' "75s/name/$USERNAME/g" "$keep_path"/app.js
sed -i '' "75s/where/$snb/g" "$keep_path"/app.js
curl -sSL https://raw.githubusercontent.com/ocarmelo/sbox/main/serv00keep.sh -o serv00keep.sh && chmod +x serv00keep.sh
else
red "未安装脚本，请选择1进行安装" && exit
fi
}

resservsb(){
if [[ -e $WORKDIR/config.json ]]; then
yellow "重启中……请稍后……"
cd $WORKDIR
ps aux | grep '[r]un -c con' | awk '{print $2}' | xargs -r kill -9 > /dev/null 2>&1
sbb=$(cat sb.txt)
nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
sleep 1
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
sleep 5
if pgrep -x "$sbb" > /dev/null; then
green "$sbb 主进程重启成功"
else
red "$sbb 主进程重启失败"
fi
cd
else
red "未安装脚本，请选择1进行安装" && exit
fi
}

menu() {
   clear
   echo "============================================================"
   green  "1. 一键安装 sing-box 和网页保活"
   echo   "------------------------------------------------------------"
   red    "2. 卸载删除 sing-box"
   echo   "------------------------------------------------------------"
   green  "3. 重启主进程"
   echo   "------------------------------------------------------------"
   green  "4. 更新脚本"
   echo   "------------------------------------------------------------"
   green  "5. 查看各节点分享"
   echo   "------------------------------------------------------------"
   green  "6. 查看sing-box与clash配置文件"
   echo   "------------------------------------------------------------"
   yellow "7. 重置并随机生成新端口 (脚本安装前后都可执行)"
   echo   "------------------------------------------------------------"
   yellow "8. 清理所有服务进程与文件 (系统初始化)"
   echo   "------------------------------------------------------------"
   red    "0. 退出脚本"
   echo   "============================================================"
ym=("$HOSTNAME" "cache$nb.serv00.com" "web$nb.serv00.com")
rm -rf $WORKDIR/ip.txt
for host in "${ym[@]}"; do
response=$(curl -sL --connect-timeout 5 --max-time 7 "https://ss.fkj.pp.ua/api/getip?host=$host")
if [[ "$response" =~ (unknown|not|error) ]]; then
dig @8.8.8.8 +time=5 +short $host | sort -u >> $WORKDIR/ip.txt
sleep 1  
else
while IFS='|' read -r ip status; do
if [[ $status == "Accessible" ]]; then
echo "$ip: 可用" >> $WORKDIR/ip.txt
else
echo "$ip: 被墙" >> $WORKDIR/ip.txt
fi	
done <<< "$response"
fi
done
if [[ ! "$response" =~ (unknown|not|error) ]]; then
grep ':' $WORKDIR/ip.txt | sort -u -o $WORKDIR/ip.txt
fi
green "Serv00服务器名称：${snb}"
echo
green "当前可选择的IP如下："
cat $WORKDIR/ip.txt
if [[ -e $WORKDIR/config.json ]]; then
echo "如默认节点IP被墙，可在客户端地址更换以上任意一个显示可用的IP"
fi
echo
portlist=$(devil port list | grep -E '^[0-9]+[[:space:]]+[a-zA-Z]+' | sed 's/^[[:space:]]*//')
if [[ -n $portlist ]]; then
green "已设置的端口如下："
echo -e "$portlist"
else
yellow "未设置端口"
fi
echo

   echo -e "========================================================="
   reading "请输入选择【0-8】: " choice
   echo
    case "${choice}" in
        1) install_singbox ;;
        2) uninstall_singbox ;; 
	3) resservsb ;;
	4) fastrun && green "脚本已更新成功" && sleep 2 && sb ;; 
        5) showlist ;;
	6) showsbclash ;;
        7) resallport ;;
        8) kill_all_tasks ;;
	0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 8" ;;
    esac
}
menu
