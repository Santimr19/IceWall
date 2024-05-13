import pandas as pd
import os
from collections import defaultdict, Counter
from tqdm import tqdm

archivo_csv = 'C:/Users/santi/Documents/TFG_Info/DataSheet/TrafficLabelling/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
csv_files = ["Friday-WorkingHours-Afternoon-DDos.pcap_ISCX",]
number="0123456789"
main_labels=["Flow ID","Source IP","Source Port","Destination IP","Destination Port","Protocol","Timestamp","Flow Duration","Total Fwd Packets",
   "Total Backward Packets","Total Length of Fwd Packets","Total Length of Bwd Packets","Fwd Packet Length Max","Fwd Packet Length Min",
   "Fwd Packet Length Mean","Fwd Packet Length Std","Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std",
   "Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max",
   "Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags",
   "Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s","Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std",
   "Packet Length Variance","FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count","CWE Flag Count",
   "ECE Flag Count","Down/Up Ratio","Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size","faulty-Fwd Header Length","Fwd Avg Bytes/Bulk",
   "Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate","Subflow Fwd Packets","Subflow Fwd Bytes",
   "Subflow Bwd Packets","Subflow Bwd Bytes","Init_Win_bytes_forward","Init_Win_bytes_backward","act_data_pkt_fwd",
   "min_seg_size_forward","Active Mean","Active Std","Active Max","Active Min","Idle Mean","Idle Std","Idle Max","Idle Min","Label","External IP"]

main_labels2=main_labels
main_labels=( ",".join( i for i in main_labels ) )
main_labels=main_labels+"\n"
flag=True

ths = open(str(csv_files[0])+".csv", "w")
ths.write(main_labels)
with open(archivo_csv, "r") as file:
    while True:
        try:
            line=file.readline()
            if  line[0] in number:# this line eliminates the headers of CSV files and incomplete streams .
                if " – " in str(line): ##  if there is "–" character ("–", Unicode code:8211) in the flow ,  it will be chanced with "-" character ( Unicode code:45).
                    line=(str(line).replace(" – "," - "))
                line=(str(line).replace("inf","0"))
                line=(str(line).replace("Infinity","0"))
                line=(str(line).replace("NaN","0"))
                    
                ths.write(str(line))
            else:
                continue                       
        except:
            break
ths.close()


df = pd.read_csv(str(csv_files[0])+".csv")
df=df.fillna(0)

string_features=["Flow Bytes/s","Flow Packets/s"]
for ii in string_features: #Some data in the "Flow Bytes / s" and "Flow Packets / s" columns are not numeric. Fixing this bug in this loop
    df[ii]=df[ii].replace('Infinity', -1)
    df[ii]=df[ii].replace('NaN', 0)
    number_or_not=[]
    for iii in df[ii]:
        try:
            k=int(float(iii))
            number_or_not.append(int(k))
        except:
            number_or_not.append(iii)
    df[ii]=number_or_not



string_features=["Flow Bytes/s","Flow Packets/s"]
for ii in string_features: #Some data in the "Flow Bytes / s" and "Flow Packets / s" columns are not numeric. Fixing this bug in this loop
    df[ii]=df[ii].replace('Infinity', -1)
    df[ii]=df[ii].replace('NaN', 0)
    number_or_not=[]
    for iii in df[ii]:
        try:
            k=int(float(iii))
            number_or_not.append(int(k))
        except:
            number_or_not.append(iii)
    df[ii]=number_or_not

# Filtramos por protocolo TCP para enfocarnos en escaneos de puertos
df_tcp = df[(df['Protocol'] == 6) | (df['Protocol'] == 17)]
print(df_tcp)
N = 3000  #Número de paquetes a partir del cual una IP será bloqueada
T = 1 #Tiempo en horas que la IP será bloqueada.
# Preprocesar y agrupar datos por IP origen

puertos = defaultdict(Counter)
for _, fila in df_tcp.iterrows():
    ip_origen = fila['Source IP']
    puerto_destino = fila['Destination Port']
    puertos[puerto_destino][ip_origen] += 1

max_ataques = 0
puerto_atacado = None
for puerto, ips in tqdm(puertos.items()):
    total_ataques = sum(ips.values())
    if total_ataques > max_ataques:
        max_ataques = total_ataques
        puerto_atacado = puerto

archivo_ips_sospechosas = 'C:/Users/santi/Documents/TFG_Info/DataSheet/DDoS/ips_sospechosas.txt'
archivo_reglas_nftables = 'C:/Users/santi/Documents/TFG_Info/DataSheet/DDoS/reglas_nftables.txt'
sospechosos = set()
if puerto_atacado is not None:
    ips_atacantes = puertos[puerto_atacado]
    for ip, c in ips_atacantes.items():
        if c > N:
            sospechosos.add(ip)

# Guardamos las IPs sospechosas en un archivo
archivo_ips_sospechosas = 'C:/Users/santi/Documents/TFG_Info/DataSheet/DDoS/ips_sospechosas.txt'
with open(archivo_ips_sospechosas, 'w') as file:
    for ip in sospechosos:
        file.write(ip + '\n')

# Generamos y guardamos las reglas de nftables
archivo_reglas_nftables = 'C:/Users/santi/Documents/TFG_Info/DataSheet/DDoS/reglas_nftables.txt'
with open(archivo_reglas_nftables, 'w') as file:
    for ip in sospechosos:
        regla = f"nft add rule ip filter input ip saddr {ip} drop ip saddr {ip} time after {T}h counter drop\n"
        file.write(regla)

print("Archivos generados:", archivo_ips_sospechosas, archivo_reglas_nftables)

