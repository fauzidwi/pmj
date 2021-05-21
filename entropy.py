import subprocess
import time
import datetime
import pandas as pd
import math
import sys

try:
    while True:
        cetakWaktu = open("Waktu Per 50 Detik.txt", "a+")
        waktu=time.time()
    
        timeAwal = (waktu)*1000
        waktuAwal = int(timeAwal)

        timeAkhir = (waktu-50)*1000
        waktuAkhir = int(timeAkhir)

        waktu1 = time.time()
        selisih = waktu1- waktu

        # cetakWaktu.write("Waktu Awal : "+str(waktuAwal)+"\nWaktu Akhir: "+str(waktuAkhir)+"\n\n")
        cetakWaktu.write("Waktu Awal : "+str(waktuAwal)+"\nWaktu Akhir: "+str(waktuAkhir)+"\nSelisih    : "+str(selisih)+"\n\n")
        cetakWaktu.close()

        subprocess.check_call(["mongoexport",
                         "--db", "mnemosyne", "--collection",
                         "session", "--type=csv",
                         "--fields=protocol,source_ip,destination_ip,identifier,honeypot",
                         "-q", """{"timestamp":{$gt:new Date(%s),$lt:new Date(%s)}}""" % (waktuAkhir, waktuAwal),
                         "--out",
                         "PacketMHN/%s.csv" % waktuAwal])
    
        readRow = pd.read_csv('PacketMHN/%s.csv' % waktuAwal)
        b = readRow[['protocol', 'source_ip', 'destination_ip']]
                
        data = {}
        cekproto = {}
        probaPacket = []

        for i in b.index:
            temp = (b['protocol'][i],b['source_ip'][i],b['destination_ip'][i])
            print(temp)
            print(type(temp))
            if temp in data:
                data[temp] += 1

            else:
                data[temp] = 1

        for items in sorted(data, key=data.get):
            print("Jumlah IP : %d IP : %s" % (data[items], items))

            probaPacket.append(float(data[items]) / len(b))
            print(float(data[items]) / len(b))

        entropy = 0
        for entro in probaPacket:
            entropy = entropy + (-entro * math.log(entro, 2))
        print 'Entropy : ' + str(entropy) + '\n'

        if entropy > 1:
            cetakEntropy = open("entropyDDOS.txt", "a+")
            waktuEntropy = datetime.datetime.now()
            cetakEntropy.write(str(waktuEntropy)+" : "+str(entropy)+"\n")
            cetakEntropy.close()
            # mitigasi
            for items in sorted(data, key=data.get):
                temp = items[0]
                if temp in cekproto:
                    cekproto[temp] += 1
                else:
                    cekproto[temp] = 1

            maks = 0
            protoblock = ''
            for items in sorted(cekproto, key=cekproto.get):
                if cekproto[items] >= maks:
                    maks = cekproto[items]
                    protoblock = items

            print("protocol DDOS :"+protoblock+"; jumlah serangan :"+str(maks))
        else:
            cetakEntropy = open("entropyNormal.txt", "a+")
            waktuEntropy = datetime.datetime.now()
            cetakEntropy.write(str(waktuEntropy)+" : "+str(entropy)+"\n")
            cetakEntropy.close()
            
        time.sleep(50)

except KeyboardInterrupt:
    sys.exit(0)
