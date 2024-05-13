import pandas as pd
from collections import defaultdict
from datetime import datetime, timedelta
from tqdm import tqdm

# Función para parsear las marcas de tiempo
def parse_timestamp(timestamp_str):
    return datetime.strptime(timestamp_str, "%d/%m/%Y %H:%M")

# Cargar el archivo CSV
archivo_csv = 'C:/Users/santi/Documents/TFG_Info/DataSheet/TrafficLabelling/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
df_full = pd.read_csv(archivo_csv)
print(df_full)

# Filtramos por protocolo TCP para enfocarnos en escaneos de puertos
df_tcp = df_full[(df_full['Protocol'] == 6) | (df_full['Protocol'] == 17)]
print(df_tcp)

N = 500  # Número de puertos distintos
K = 10  # Intervalo de tiempo en minutos

# Preprocesar y agrupar datos por IP origen
conexiones = defaultdict(list)
for _, fila in df_tcp.iterrows():
    ip_origen = fila['Source IP']
    puerto_destino = fila['Destination Port']
    timestamp = parse_timestamp(fila['Timestamp'])
    conexiones[ip_origen].append((puerto_destino, timestamp))

# Analizar datos para detectar IPs sospechosas
sospechosos = set()
for ip, datos in tqdm(conexiones.items()):
    puertos_timestamps = defaultdict(list)
    for puerto, timestamp in datos:
        puertos_timestamps[puerto].append(timestamp)
    
    # Contar puertos distintos intentados en un intervalo de K minutos
    todos_timestamps = sorted([ts for sublist in puertos_timestamps.values() for ts in sublist])
    for i in range(len(todos_timestamps)):
        ventana_inicio = todos_timestamps[i]
        ventana_final = ventana_inicio + timedelta(minutes=K)
        puertos_ventana = {puerto for puerto, timestamps in puertos_timestamps.items() if any(ventana_inicio <= ts <= ventana_final for ts in timestamps)}
        if len(puertos_ventana) > N:
            sospechosos.add(ip)
            break  # No necesitamos seguir revisando esta IP si ya se considera sospechosa


# Guardamos las IPs sospechosas en un archivo
archivo_ips_sospechosas = 'C:/Users/santi/Documents/TFG_Info/DataSheet/PortScan/ips_sospechosas.txt'
with open(archivo_ips_sospechosas, 'w') as file:
    for ip in sospechosos:
        file.write(ip + '\n')

# Generamos y guardamos las reglas de nftables
archivo_reglas_nftables = 'C:/Users/santi/Documents/TFG_Info/DataSheet/PortScan/reglas_nftables.txt'
with open(archivo_reglas_nftables, 'w') as file:
    for ip in sospechosos:
        regla = f"nft add rule ip filter input ip saddr {ip} drop\n"
        file.write(regla)

archivo_ips_sospechosas, archivo_reglas_nftables
