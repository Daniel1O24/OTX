About

Get open Threat Intelligence of IPv4 addresses list from OTX Community and save the results to a csv file automatically.

Installation
1. download and install Python 3.10 (other python3 version may also work, But I only tested on Python 3.10)
https://www.python.org/downloads/
2. install Python modules: requests and pandas
   
  pip3 install requests

  pip3 install pandas

Example

  1.Put the suspecious IPv4 addresses in the IPv4 column of IPv4.csv file, for example, the Top 400 IP addresses in Snort block IP list.
  
  2.run the python script bellow, you will get the threat intellience of these IP addresses from OTX and save the results to a csv file automatically.
  
  python3 OTX.py

