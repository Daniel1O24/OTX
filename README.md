![image](https://github.com/user-attachments/assets/47260fea-5062-450f-bde2-3347aab1fa1b)![image](https://github.com/user-attachments/assets/66db6e7c-5e0f-454a-acff-0ae52247baf5)About

During the defensive security of important events, such as Olympic Games, defenders may need to block hundreds of malicious IP in a day. Cyber threat intelligence is one of best practises of cyber security. This python tool can get hundreds rows of open Threat Intelligence of IPv4 addresses list from the OTX Community and save the results to a csv file automatically. 

Features
1. support Pulse count, False Positive, validation, Location, ASN, Indicator Facts and Related Tags of IP address thread intelligence from OTX
2. resilience design: if the tool gets one part of threat intelligence of IP address from OTX fail, it will still get other parts; if it gets the whole thread inelligence of one IP address fail, it will still get other IP addresses' thread intelligence.
3. the results is saved to safe CSV file, not Excel. 

Installation
1. download and install Python 3.10 (other python3 version may also work, But I only tested on Python 3.10)
https://www.python.org/downloads/
2. install Python modules: requests and pandas
  pip3 install requests
  pip3 install pandas

Example

1.Put the suspecious IPv4 addresses in the IPv4 column of IPv4.csv file, for example, the Top 100 IP addresses in Snort block IP list.
2.run the python script bellow,  get the threat intelligence of these IP addresses from OTX and save the results to a csv file automatically.
  python3 OTX.py

Thanks to the Atos security team who shared the OTX during Olympic Games, which inspired me to design and develop this python tool again during my travels abroad.

PS: I made this automation tool in my spare time. If the tool helps you save some time or you just want to support more people to develop more free and open source software, Bitcoin can be used to make donations.

Segwit
Bitcoin address
bc1q7nwyjcwhsexx3g5pne6lwumnn3kkkylux426xc
![IMG_E0011](https://github.com/user-attachments/assets/b4a5faba-c531-4696-a968-031c8b4d07bf)


Legacy
Bitcoin address
14qt6U1hyBEwcYgcZvqbUrETAqqhRnM1xB
![IMG_E0012](https://github.com/user-attachments/assets/1e6b4e8e-e240-44b4-aca2-81bc0ffaf0d9)






