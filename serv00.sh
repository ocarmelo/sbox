#!/bin/bash
export LC_ALL=C
HOSTNAME=$(hostname)
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
export UUID=${UUID:-$(echo -n "$USERNAME+$HOSTNAME" | md5sum | head -c 32 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')}
export NEZHA_SERVER=${NEZHA_SERVER:-''}             
export NEZHA_PORT=${NEZHA_PORT:-''}            
export NEZHA_KEY=${NEZHA_KEY:-''}
export CHAT_ID=${CHAT_ID:-''} 
export BOT_TOKEN=${BOT_TOKEN:-''} 
export UPLOAD_URL=${UPLOAD_URL:-''}
export SUB_TOKEN=${SUB_TOKEN:-${UUID:0:8}}

[[ "$HOSTNAME" == "s1.ct8.pl" ]] && WORKDIR="$HOME/domains/${USERNAME}.ct8.pl/logs" && FILE_PATH="${HOME}/domains/${USERNAME}.ct8.pl/public_html" || WORKDIR="$HOME/domains/${USERNAME}.serv00.net/logs" && FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"
rm -rf "$WORKDIR" && mkdir -p "$WORKDIR" "$FILE_PATH" && chmod 777 "$WORKDIR" "$FILE_PATH" >/dev/null 2>&1
bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
command -v curl &>/dev/null && COMMAND="curl -so" || command -v wget &>/dev/null && COMMAND="wget -qO" || { red "Error: neither curl nor wget found, please install one of them." >&2; exit 1; }

check_port () {
  clear
  echo -e "\e[1;35m正在安装中,请稍等...\e[0m"
  port_list=$(devil port list)
  tcp_ports=$(echo "$port_list" | grep -c "tcp")
  udp_ports=$(echo "$port_list" | grep -c "udp")

  if [[ $udp_ports -lt 1 ]]; then
      echo -e "\e[1;91m没有可用的UDP端口,正在调整...\e[0m"

      if [[ $tcp_ports -ge 3 ]]; then
          tcp_port_to_delete=$(echo "$port_list" | awk '/tcp/ {print $1}' | head -n 1)
          devil port del tcp $tcp_port_to_delete
          echo -e "\e[1;32m已删除TCP端口: $tcp_port_to_delete\e[0m"
      fi

      while true; do
          udp_port=$(shuf -i 10000-65535 -n 1)
          result=$(devil port add udp $udp_port 2>&1)
          if [[ $result == *"succesfully"* ]]; then
              echo -e "\e[1;32m已添加UDP端口: $udp_port"
              udp_port1=$udp_port
              break
          else
              echo -e "\e[1;33m端口 $udp_port 不可用，尝试其他端口...\e[0m"
          fi
      done

      echo -e "\e[1;32m端口已调整完成,如安装完后节点不通,访问 /restart域名重启\e[0m"
      devil binexec on >/dev/null 2>&1
      # kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
  else
      udp_ports=$(echo "$port_list" | awk '/udp/ {print $1}')
      udp_port1=$(echo "$udp_ports" | sed -n '1p')

      echo -e "\e[1;35mhysteria2使用udp端口: $udp_port1\e[0m"
  fi

  export PORT=$udp_port1
}
check_port

ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi
FILE_INFO=("$BASE_URL/hy2 web")
if [ -n "$NEZHA_PORT" ]; then
    FILE_INFO+=("$BASE_URL/npm npm")
else
    FILE_INFO+=("$BASE_URL/v1 php")
    cat > "${WORKDIR}/config.yaml" << EOF
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 1
server: ${NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: false
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}
EOF
fi
declare -A FILE_MAP
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyz1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
    
    $COMMAND "$NEW_FILENAME" "$URL"
    echo -e "\e[1;32mDownloading $NEW_FILENAME\e[0m"
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
done
wait

# Generate cert
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout "$WORKDIR/server.key" -out "$WORKDIR/server.crt" -subj "/CN=bing.com" -days 36500

get_ip() {
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

echo -e "\e[1;32m获取可用IP中,请稍等...\e[0m"
HOST_IP=$(get_ip)
echo -e "\e[1;35m当前选择IP为: $HOST_IP 如安装完后节点不通可尝试重新安装\e[0m"

cat << EOF > config.yaml
listen: $HOST_IP:$PORT

tls:
  cert: "$WORKDIR/server.crt"
  key: "$WORKDIR/server.key"

auth:
  type: password
  password: "$UUID"

fastOpen: true

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true

transport:
  udp:
    hopInterval: 30s
EOF

install_keepalive () {
    echo -e "\n\e[1;35m正在安装保活服务中,请稍等......\e[0m"
    keep_path="$HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs"
    [ -d "$keep_path" ] || mkdir -p "$keep_path"
    app_file_url="https://hy2.ssss.nyc.mn/app.js"
    $COMMAND $COMMAND "${keep_path}/app.js" "$app_file_url" 

    cat > ${keep_path}/.env <<EOF
UUID=${UUID}
SUB_TOKEN=${SUB_TOKEN}
UPLOAD_URL=${UPLOAD_URL}
TELEGRAM_CHAT_ID=${CHAT_ID}
TELEGRAM_BOT_TOKEN=${BOT_TOKEN}
NEZHA_SERVER=${NEZHA_SERVER}
NEZHA_PORT=${NEZHA_PORT}
NEZHA_KEY=${NEZHA_KEY}
EOF
    devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
    index_url="https://github.com/eooce/Sing-box/releases/download/00/index.html"
    [ -f "${FILE_PATH}/index.html" ] || $COMMAND "${FILE_PATH}/index.html" "$index_url"
    devil www add keep.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1
    ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
    ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
    rm -rf $HOME/.npmrc > /dev/null 2>&1
    cd ${keep_path} && npm install dotenv axios --silent > /dev/null 2>&1
    rm $HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
    # devil www options keep.${USERNAME}.serv00.net sslonly on > /dev/null 2>&1
    devil www restart keep.${USERNAME}.serv00.net > /dev/null 2>&1
    if curl -skL "http://keep.${USERNAME}.serv00.net/start" | grep -q "running"; then
        echo -e "\e[1;32m\n全自动保活服务安装成功\n\e[0m"
	    echo -e "\e[1;32m所有服务都运行正常,全自动保活任务添加成功\n\n\e[0m"
        echo -e "\e[1;35m访问 http://keep.${USERNAME}.serv00.net/restart 重启进程\n\e[0m"
        echo -e "\e[1;35m访问 http://keep.${USERNAME}.serv00.net/list 全部进程列表\n\e[0m"
        echo -e "\e[1;33m访问 http://keep.${USERNAME}.serv00.net/start 调起保活程序\n\e[0m"
        echo -e "\e[1;35m访问 http://keep.${USERNAME}.serv00.net/status 查看进程状态\n\e[0m"
        echo -e "\e[1;35m如果需要TG通知,在\e[1;33m https://t.me/laowang_serv00_bot \e[1;35m获取CHAT_ID,并带CHAT_ID环境变量运行\n\n\e[0m"
    else
        echo -e "\e[1;31m\n全自动保活服务安装失败,存在未运行的进程,访问 \e[0mhttp://keep.${USERNAME}.serv00.net/status \e[1;31m检查,建议执行以下命令后重装: \n\ndevil www del ${USERNAME}.serv00.net\ndevil www del keep.${USERNAME}.serv00.net\nrm -rf $HOME/domains/*\nshopt -s extglob dotglob\nrm -rf $HOME/!(domains|mail|repo|backups)\n\n\e[0m"
    fi
}



get_name() { if [ "$HOSTNAME" = "s1.ct8.pl" ]; then SERVER="CT8"; else SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1); fi; echo "$SERVER"; }
NAME="$(get_name)-hysteria2-${USERNAME}"

ISP=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")

echo -e "\n\e[1;32mHysteria2安装成功\033[0m\n"
echo -e "\e[1;33mV2rayN 或 Nekobox、小火箭等直接导入,跳过证书验证需设置为true\033[0m\n"
cat > ${FILE_PATH}/${SUB_TOKEN}_hy2.log <<EOF
hysteria2://$UUID@$HOST_IP:$PORT/?sni=www.bing.com&alpn=h3&insecure=1#$ISP-$NAME

EOF
cat ${FILE_PATH}/${SUB_TOKEN}_hy2.log
echo -e "\n\e[1;35mClash: \033[0m"
cat << EOF
- name: $ISP-$NAME
  type: hysteria2
  server: $HOST_IP
  port: $PORT
  password: $UUID
  alpn:
    - h3
  sni: www.bing.com
  skip-cert-verify: true
  fast-open: true
EOF
echo ""
QR_URL="https://00.ssss.nyc.mn/qrencode"
$COMMAND "${WORKDIR}/qrencode" "$QR_URL" && chmod +x "${WORKDIR}/qrencode"
"${WORKDIR}/qrencode" -m 2 -t UTF8 "https://${USERNAME}.serv00.net/${SUB_TOKEN}_hy2.log"
echo -e "\n\e[1;35m节点订阅链接: https://${USERNAME}.serv00.net/${SUB_TOKEN}_hy2.log  适用于V2ranN/Nekobox/Karing/小火箭/sterisand/Loon 等\033[0m\n"
rm -rf config.yaml fake_useragent_0.2.0.json
install_keepalive
echo -e "\e[1;35m老王serv00|CT8单协议hysteria2无交互一键安装脚本\e[0m"
echo -e "\e[1;35m脚本地址: https://github.com/eooce/sing-box\e[0m"
echo -e "\e[1;35m反馈论坛: https://bbs.vps8.me\e[0m"
echo -e "\e[1;35mTG反馈群组: https://t.me/vps888\e[0m"
echo -e "\e[1;35m转载请著名出处,请勿滥用\e[0m\n"
echo -e "\e[1;32mRuning done!\033[0m\n"

resservsb(){
if [[ -e $WORKDIR/config.json ]]; then
yellow "重启中……请稍后……"
cd $WORKDIR
ps aux | grep '[r]un -c con' | awk '{print $2}' | xargs -r kill -9 > /dev/null 2>&1
sbb=$(cat sb.txt)
nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
sleep 1
curl -sk "http://${snbok}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
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
  echo ""
  purple "=== Serv00 sing-box一键二协议安装脚本修改版 ===\n"
  echo -e "${green}脚本地址：${re}${yellow}https://github.com/eooce/Sing-box${re}\n"
  echo -e "${green}反馈论坛：${re}${yellow}https://bbs.vps8.me${re}\n"
  echo -e "${green}TG反馈群组：${re}${yellow}https://t.me/vps888${re}\n"
  purple "转载请著名出处，请勿滥用\n"
  yellow "快速启动命令00\n"
  green "1. 安装sing-box"
  echo  "==============="
  green "2. 安装全自动保活"
  echo  "==============="
  red "3. 卸载sing-box"
  echo  "==============="
  green "4. 重启主进程"
  echo  "==============="
  green "5. 查看节点信息"
  echo  "==============="
  green "6. 查看保活链接"
  echo  "==============="
  yellow "7. 更换节点端口"
  echo  "==============="
  yellow "8. 初始化系统"
  echo  "==============="
  red "0. 退出脚本"
  echo "==========="
  reading "请输入选择(0-7): " choice
  echo ""
  case "${choice}" in
      1) install_singbox ;;
      2) install_livealive ;;
      3) uninstall_singbox ;; 
	  4) resservsb ;;
      5) get_nodes ;; 
      6) get_url_info ;;
      7) changge_ports ;;
      8) reset_system ;;
      0) exit 0 ;;
      *) red "无效的选项，请输入 0 到 7" ;;
  esac
}
menu

