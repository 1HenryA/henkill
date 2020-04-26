#!/bin/bash
#
#  Copyright 2017 Henry <henry.antifa@icloud.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#

export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'

modprobe ip_tables


function limparegras(){
echo -n "Limpando Regras ........................................... "
 # Limpando as Chains
 iptables -F INPUT
 iptables -F OUTPUT
 iptables -F FORWARD
 iptables -F -t filter
 iptables -F POSTROUTING -t nat
 iptables -F PREROUTING -t nat
 iptables -F OUTPUT -t nat
 iptables -F -t nat
 iptables -t nat -F
 iptables -t mangle -F
 iptables -X
 # Zerando contadores
 iptables -Z
 iptables -t nat -Z
 iptables -t mangle -Z
 # Define as políticas padrão ACCEPT
 iptables -P INPUT ACCEPT
 iptables -P OUTPUT ACCEPT
 iptables -P FORWARD ACCEPT
}



function ativaping(){
 echo -n "Ativando ICMP ............................................. "
 echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all
}


function desativaprotecao(){
 echo -n "Removendo Regras de Proteção .............................. "
 i=/proc/sys/net/ipv4
 echo "1" > /proc/sys/net/ipv4/ip_forward
 echo "0" > $i/tcp_syncookies
 echo "0" > $i/icmp_echo_ignore_broadcasts
 echo "0" > $i/icmp_ignore_bogus_error_responses
 for i in /proc/sys/net/ipv4/conf/*; do
   echo "1" > $i/accept_redirects
   echo "1" > $i/accept_source_route
   echo "0" > $i/log_martians
   echo "0" > $i/rp_filter
 done
}

function limpatabelas(){
echo -n "Limpando Regras ........................................... "
# Limpando tabelas
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
}

function ativaprotecao(){
echo -n "Ativando Proteção ......................................... "
# Ativando algumas coisas básicas do kernel
echo 1 > /proc/sys/net/ipv4/tcp_syncookies                     # Habilita o uso de syncookies (muito útil para evitar SYN flood attacks)
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all               # Desabilita o "ping" (Mensagens ICMP) para sua máquina
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects          # Não aceita redirecionar pacotes ICMP
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses  # Ativa a proteção contra respostas a mensagens de erro falsas
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts        # Evita a peste do Smurf Attack e alguns outros de redes locais
}
function politicaspadrao(){
echo -n "Configurando Padrões ...................................... "
# Configurando as políticas padrões
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Loga/Adiciona/Descarta hosts da lista "SUSPEITO" (cuja conexão não cumpre nenhuma das regras acima) {deixe como última regra!}
iptables -A INPUT -p tcp --dport=20 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
iptables -A INPUT -p udp --dport=20 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
iptables -A INPUT -p tcp --dport=21 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
iptables -A INPUT -p udp --dport=21 -j LOG --log-level warning --log-prefix "[firewall] [ftp]"
iptables -A INPUT -p tcp --dport=22 -j LOG --log-level warning --log-prefix "[firewall] [ssh]"
iptables -A INPUT -p udp --dport=22 -j LOG --log-level warning --log-prefix "[firewall] [ssh]"
iptables -A INPUT -p tcp --dport=23 -j LOG --log-level warning --log-prefix "[firewall] [telnet]"
iptables -A INPUT -p udp --dport=23 -j LOG --log-level warning --log-prefix "[firewall] [telnet]"
iptables -A INPUT -p icmp  -j LOG --log-level warning --log-prefix "[firewall] [ping]"
}

function permitirloop(){
echo -n "Permitindo LoopBack ....................................... "
# Permitindo loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permite o estabelecimento de novas conexões iniciadas por você // coração do firewall //
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED,NEW -j ACCEPT
}
function dns(){
echo -n "Ativando DNS .............................................. "
# Libera o acesso do DNS (troque pelo seu, caso não use o DNS do google. Caso não saiba exclua a opção -s apagando até antes do -j)
iptables -A INPUT -p udp --sport 53  -j ACCEPT
iptables -A INPUT -p udp --sport 53  -j ACCEPT

# Liberando portas de serviços externos (descomente e altere conforme sua necessidade)
# iptables -A INPUT -p tcp -m multiport --dport 21,22,53,80,443,3128,8080 -j ACCEPT

#--- Criando listas de bloqueios

# Descarta pacotes reincidentes/persistentes da lista SUSPEITO (caso tenha 5 entradas ficará 1H em DROP / caso tenha 10 ficará 24H em DROP)
iptables -A INPUT -m recent --update --hitcount 10 --name SUSPEITO --seconds 86400 -j DROP
iptables -A INPUT -m recent --update --hitcount 5 --name SUSPEITO --seconds 3600 -j DROP

# Descarta pacotes reincidentes/persistentes da lista SYN-DROP (caso tenha 5 entradas ficará 1H em DROP / caso tenha 10 ficará 24H em DROP)
iptables -A INPUT -m recent --update --hitcount 10 --name SYN-DROP --seconds 86400 -j DROP
iptables -A INPUT -m recent --update --hitcount 5 --name SYN-DROP --seconds 3600 -j DROP
}
function criachain(){
echo -n "Criando Chains ............................................ "
# Cria a CHAIN "SYN"
iptables -N SYN
iptables -A SYN -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [SYN: DROP]"
iptables -A SYN -m limit --limit 10/min --limit-burst 3 -m recent --set --name SYN-DROP -j DROP
iptables -A SYN -m limit --limit 1/min --limit-burst 1 -j LOG --log-level warning --log-prefix "[firewall] [SYN: FLOOD!]"
iptables -A SYN -j DROP

# Cria a CHAIN "SCANNER"
iptables -N SCANNER
iptables -A SCANNER -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [SCANNER: DROP]"
iptables -A SCANNER -m limit --limit 10/min --limit-burst 3 -m recent --set --name SUSPEITO -j DROP
iptables -A SCANNER -m limit --limit 1/min --limit-burst 1 -j LOG --log-level warning --log-prefix "[firewall] [SCANNER: FLOOD!]"
iptables -A SCANNER -j DROP

#--- Bloqueios

# Rejeita os restos de pacotes após fechar o torrent (subistitua 12300 pela porta do seu torrent)
iptables -A INPUT -p tcp --dport 12300 -j REJECT
iptables -A INPUT -p udp --dport 12300 -j DROP

# Manda os pacotes SYN suspeitos (não liberados acima) para a chain "SYN"
iptables -A INPUT -p tcp --syn -m state --state NEW -j SYN

# Adicionando regras para CHAIN "SCANNER"
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL ACK -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL PSH,URG,FIN -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j SCANNER
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j SCANNER
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL FIN -j SCANNER

# Descarta pacotes inválidos
iptables -A INPUT -m state --state INVALID -j DROP

# Bloqueia portas
iptables -A INPUT -p tcp --dport=20 -j DROP
iptables -A INPUT -p udp --dport=20 -j DROP
iptables -A INPUT -p tcp --dport=21 -j DROP
iptables -A INPUT -p udp --dport=21 -j DROP
iptables -A INPUT -p tcp --dport=22 -j DROP
iptables -A INPUT -p udp --dport=22 -j DROP
iptables -A INPUT -p tcp --dport=23 -j DROP
iptables -A INPUT -p udp --dport=23 -j DROP
iptables -A INPUT -m recent --update --name SUSPEITO -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[firewall] [suspeito]"
iptables -A INPUT -m limit --limit 10/min --limit-burst 3 -m recent --set --name SUSPEITO -j DROP
iptables -A INPUT -j DROP
}

function help(){
    printf ${blue}
    echo -e "+-------------------------------------------+"
    echo -e "| Henkill 1.0 - Configuração iptables       |"
    echo -e "| Copyright (C) 2017 Henry                  |"
    echo -e "|                                           |"
    echo -e "| Contato: henry.antifa@icloud.com          |"
    echo -e "+-------------------------------------------+"

    printf "${white}%s${endc}\\n"
    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\\n" \
        "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\\n" "└───╼" "henkill --argumento"

    printf "\\n${green}%s${endc}\\n" "Argumentos:"
    printf "${white}%s${endc}\\n"

    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--help"    "mostra essa mensagem de ajuda"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--start"   "inicia o henkill e configura o iptables"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--stop"    "para o henkill e reseta configurações do iptables"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--restart" "reinicia o henkill e reconfigura o iptables"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--status"  "checa o status do programa"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--checkip" "checa online o IP público"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--list"    "lista as regras em todas as chains"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--version" "mostra a versão do programa e do iptables"
}

function start(){

    printf ${blue}
    echo -e "+-------------------------------------------+"
    echo -e "| Henkill 1.0 - Configuração iptables       |"
    echo -e "| Copyright (C) 2017 Henry                  |"
    echo -e "|                                           |"
    echo -e "| Contato: henry.antifa@icloud.com          |"
    echo -e "+-------------------------------------------+"

printf "${white}%s${endc}\\n"

 if limpatabelas
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if ativaprotecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if politicaspadrao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if permitirloop
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if dns
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if criachain
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi

echo -n "Iniciando Firewall ........................................ "
echo -e  -n "[\033[01;32m  OK  \033[01;37m]"
echo

}

function stop(){

    printf ${blue}
    echo -e "+-------------------------------------------+"
    echo -e "| Henkill 1.0 - Configuração iptables       |"
    echo -e "| Copyright (C) 2017 Henry                  |"
    echo -e "|                                           |"
    echo -e "| Contato: henry.antifa@icloud.com          |"
    echo -e "+-------------------------------------------+"
printf "${white}%s${endc}\\n"

 if limparegras
  then
   echo -e "[\033[01;32m  OK  \033[01;37m] "
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if ativaping
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if desativaprotecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi

}

function restart(){
    printf ${blue}
    echo -e "+-------------------------------------------+"
    echo -e "| Henkill 1.0 - Configuração iptables       |"
    echo -e "| Copyright (C) 2017 Henry                  |"
    echo -e "|                                           |"
    echo -e "| Contato: henry.antifa@icloud.com          |"
    echo -e "+-------------------------------------------+"
printf "${white}%s${endc}\\n"

 if limparegras
  then
   echo -e "[\033[01;32m  OK  \033[01;37m] "
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if ativaping
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if desativaprotecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 echo ""
 if limpatabelas
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if ativaprotecao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if politicaspadrao
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if permitirloop
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if dns
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi
 if criachain
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m  Erro  \033[01;37m]"
 fi

echo -n "Iniciando Firewall ........................................ "
echo -e  -n "[\033[01;32m  OK  \033[01;37m]"
echo

}

function status(){
    	if iptables -L | grep "SCANNER" > /dev/null; then
		printf "${blue}%s${endc} ${green}%s${endc}\\n" \
		"[INFO] Checando se o iptables está configurado corretamente..."
        	printf "${green}%s\\n" \
                "[INFO] Firewall está configurado, continue..."
    	else
		printf "${blue}%s${endc} ${green}%s${endc}\\n" \
		"[INFO] Checando se o iptables está configurado corretamente..."
		printf ""
    		iptables -L | grep "" > /dev/null;
        	printf "${red}%s\\n" \
                "[INFO] Firewall está desconfigurado..."
    	fi
}

function checkip(){
    printf "${blue}%s\\n" \
        "[INFO] Checando online IP público, espere..."

    # curl request: http://ipinfo.io/geo
    if ! external_ip="$(curl -s -m 10 ipinfo.io/geo)"; then
        printf "${red}%s${endc}\\n" "[FAILED] curl: HTTP request error!"
        exit 1
    fi

    # Print da saída
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "[INFO]" "IP Address Details:"
    printf "${white}%s\\n" "$external_ip" | tr -d '"{}' | sed 's/ //g'
}

function list(){
	printf "${green}%s\\n" \
	"[INFO] Checando as regras..."
        echo -e "[INFO] Regras atual: "
	echo -e ${white}
	iptables -L
}

function version(){
	echo "henkill v1.0"
	iptables --version
}

case $1 in
  --help)
   help
  ;;

  --start)
   start
  ;;

  --stop)
   stop
  ;;

  --restart)
   restart
  ;;

  --status)
   status
  ;;

  --checkip)
   checkip
  ;;

  --list)
   list
  ;;

  --version)
   version
  ;;

  *)

printf "${white}%s\\n" "Henkill v1.0"
echo -e "Escrito por: Henry <henry.antifa@icloud.com>"
echo ""
echo -e "${white}""Tente 'henkill --help' para mais informações."

esac
