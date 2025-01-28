import requests
import re
from datetime import datetime
import whois

def obtener_reputacion_virustotal(ioc, apikey):
    """
    Obtiene la reputación de un IOC (IP, hash o URL) utilizando la API v3 de VirusTotal.

    Args:
      ioc: El IOC a consultar.
      apikey: La clave de API de VirusTotal.

    Returns:
      Un diccionario con la información de reputación del IOC, incluyendo el propietario de la IP si está disponible, o None si hay un error.
    """

    headers = {'x-apikey': apikey}
    url = None

    if ioc.startswith(('http://', 'https://')):  # URL
        url = f'https://www.virustotal.com/api/v3/urls/{ioc}'
    elif len(ioc) == 32 and all(c in '0123456789abcdef' for c in ioc):  # Hash MD5
        url = f'https://www.virustotal.com/api/v3/files/{ioc}'
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):  # IP (usando regex)
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
    else:
        return None  # IOC inválido

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Lanzar una excepción si hay un error HTTP

        # Verificar si la respuesta está vacía
        if not response.text:
            print(f"Error: La API de VirusTotal devolvió una respuesta vacía para {ioc}")
            return None

        data = response.json()
        
        # Extraer el propietario de la IP si está disponible
        if 'data' in data and 'attributes' in data['data'] and 'as_owner' in data['data']['attributes']:
            data['as_owner'] = data['data']['attributes']['as_owner']

        return data
    except requests.exceptions.HTTPError as e:
        print(f"Error HTTP al consultar la API de VirusTotal para {ioc}: {e} - Respuesta: {response.text}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"Error de conexión al consultar la API de VirusTotal para {ioc}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"Tiempo de espera agotado al consultar la API de VirusTotal para {ioc}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error al consultar la API de VirusTotal para {ioc}: {e}")
        return None

def obtener_informacion_whois(ip):
    """
    Obtiene información WHOIS para una IP.

    Args:
      ip: La dirección IP a consultar.

    Returns:
      Un diccionario con la información WHOIS, o None si hay un error.
    """
    try:
        w = whois.whois(ip)
        return {
            "organizacion": w.org,
            "pais": w.country,
            "correo": w.emails
        }
    except Exception as e:
        print(f"Error al obtener información WHOIS para {ip}: {e}")
        return None

def analizar_archivo_iocs(nombre_archivo, apikey):
    """
    Analiza un archivo que contiene IOCs (IPs, hashes y URLs) 
    y genera un reporte de reputación con información del propietario 
    de la IP obtenida de VirusTotal.

    Args:
      nombre_archivo: El nombre del archivo que contiene los IOCs.
      apikey: La clave de API de VirusTotal.
    """
    try:
        with open(nombre_archivo, 'r') as f:
            iocs = [linea.strip() for linea in f]
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{nombre_archivo}'")
        return

    reporte = ""
    for ioc in iocs:
        reputacion = obtener_reputacion_virustotal(ioc, apikey)

        if reputacion:
            if 'data' in reputacion and 'attributes' in reputacion['data']:
                attributes = reputacion['data']['attributes']
                if 'last_analysis_stats' in attributes:
                    stats = attributes['last_analysis_stats']
                    reporte += f"{ioc}: {stats.get('malicious', 0)}/{sum(stats.values())} detecciones"

                    # Mostrar el propietario de la IP si está disponible
                    if 'as_owner' in reputacion:
                        reporte += f" - Propietario: {reputacion['as_owner']}\n"
                    else:
                        reporte += "\n"
                else:
                    reporte += f"{ioc}: No se encontró información de reputación\n"
            else:
                reporte += f"{ioc}: No se encontró información de reputación\n"
        else:
            reporte += f"{ioc}: IOC inválido\n"

    print("\nReporte de reputación:")
    print(reporte)

    # Guardar el reporte en un archivo
    fecha_actual = datetime.now().strftime("%Y%m%d")
    nombre_archivo_reporte = f"reporte_{fecha_actual}.txt"

    try:
        with open(nombre_archivo_reporte, "w") as f:
            f.write(reporte)
        print(f"\nReporte de reputación guardado en: {nombre_archivo_reporte}")
    except Exception as e:
        print(f"Error al guardar el reporte en el archivo: {e}")

if __name__ == "__main__":
    apikey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Reemplaza con tu API key real
    nombre_archivo = input("Ingrese el nombre del archivo con los IOCs: ")
    analizar_archivo_iocs(nombre_archivo, apikey)