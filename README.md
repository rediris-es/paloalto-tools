# paloalto-tools

Scripts para equipos paloalto 

Varios scripts para equipos PaloAlto , los que Python utilizan un fichero de configuración (ver example.cfg) que permite compartir algunas cosas como
la API Key

##  vpn-report

Consulta el FW y extrae la información de los accesos VPN, es un work en progress pero puede servir, utliza el API de paloalto para hacer la consulta


## Know issues
* No funciona bien por algun motivo el modo panorama
* Por algun motivo en un cluster activo/pasivo, el pasivo genera logs de global-protect en algunos casos
* Falta generar bien el report no solo los logs

## Configuracion
Incluir en la sección del fichero de configuración ,los siguientes valores, en la entrada "[vpnreport]" (ver fichero de configuracion):

* Key = API KEY
* mode=firewall o panorama, indica si se consulta un FW o un panorama, solo funciona el modo firewall por ahora
* device = Dispositivos a consultar
* records = Registros que se van a listar despues 
* Registro que se emplea para el tiempo tine_generated suele ser
* filter = cadena de busqueda en el API

Se puede definir la variable key tambien en la sección "[main]" del fichero de configuración y el modo debug

## Command-line
* --config path del fichero de configuacion
* --debug activa el flag de debug
* --nodebug desactiva el flag de debug
* --interval : extrae los logs de un intervalo de tiempo (ver features)


## Features
* Permite extraer los logs de un periodo de tiempo, para ello en se emplea la opción --interval, pudiendo definirle:
  * yesterday = Los logs de ayer
  * week = Los logs de la ultima semana 
  * YYYY/MM/DD HH:MM:SS - YYYY/MM/DD HH:MM/SS : Muy estricto , poner entre comillas, intervalo de tiempo

