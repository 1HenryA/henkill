						Welcome to the Henkill README file!    

Henkill v1.0
=============

Uma simples ferramenta - escrita em puro bash script - para auto configurar o iptables. 

Compátivel com qualquer distro Linux.

Autor: Henry <<henry.antifa@icloud.com>>

Instalação
-----------

É recomendado atualizar sua distro:
 
    $ sudo apt update && sudo apt upgrade && sudo apt dist-upgrade

Verifique se iptables está instalado:
 
    $ sudo ap install iptables

Instale o Henkill:

    $ git clone https://github.com/1HenryA/henkill.git
    $ cd henkill/
    $ sudo make install
    
Uso
----

Use: $ sudo henkill --[argumento]

Para ver os argumentos válidos:

    $ sudo henkill --help


Desinstalação
--------------

    $ cd henkill/
    $ sudo make uninstall
    
