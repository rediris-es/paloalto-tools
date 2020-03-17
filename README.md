# paloalto-tools

Scripts para equipos paloalto 

Varios scripts para equipos PaloAlto , los que Python utilizan un fichero de configuración (ver example.cfg) que permite compartir algunas cosas como
la API Key

##  vpn-report

Consulta el FW y extrae la información de los accesos VPN, es un work en progress pero puede servir, utliza el API de paloalto para hacer la consulta


### Know issues
* No funciona bien por algun motivo el modo panorama
* Por algun motivo en un cluster activo/pasivo, el pasivo genera logs de global-protect en algunos casos
* Falta generar bien el report no solo los logs

