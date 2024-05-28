import requests
import pandas as pd
from datetime import datetime

class OTX(object):

    """
    Get the IPv4 addresses list from the csv file: IPv4.csv
    """
    def get_ipv4_list(self):
        df = pd.read_csv('IPv4.csv')
        ip_list = df['IPv4'].tolist()
        print(ip_list)
        return ip_list

    """
    Get the threat intelligence of one IPv4 address from OTX
    """
    def get_ipv4_otx(self, ip: str):
        ipv4_otx = []
        url = "https://otx.alienvault.com/api/v1/indicators/IPv4/" + str(ip)

        retry = 0
        # resilience design: if some exception happens, try three times.
        while True:
            try:
                response = requests.get(url)
                status_code = response.status_code
                if status_code == 200:
                    general = response.json()

                    try:
                        pulse_count = general['pulse_info']['count']
                    except Exception as e:
                        pulse_count = 'Exception:' + str(e)
                        print(pulse_count)

                    try:
                        false_positive_list = general['false_positive']
                        false_positive_str = ''
                        for false_positive in false_positive_list:
                            false_positive_str += 'assessment: ' + false_positive['assessment'] + "\n" + "assessment_date: " + false_positive['assessment_date'] + "\n"
                    except Exception as e:
                        false_positive_str = 'Exception:' + str(e)
                        print(false_positive_str)

                    try:
                        validation_list = general['validation']
                        validation_str = ''
                        for validation in validation_list:
                            validation_str += 'source: ' + validation['source'] + "\n" + "message: " + validation['message'] + "\n"
                    except Exception as e:
                        validation_str = 'Exception:' + str(e)
                        print(validation_str)

                    try:
                        pulses = general['pulse_info']['pulses']
                        tags = []
                        for pulse in pulses:
                            tags += pulse['tags']
                        tags_set = set(tags)

                        tags_size = len(tags_set)
                        tags_str = ''
                        for tag in tags_set:
                            tags_str += "," + tag
                        if tags_size > 0:
                            tags_str = tags_str[1:]
                    except Exception as e:
                        tags_size = 0
                        tags_str = 'Exception:' + str(e)
                        print(tags_str)

                    try:
                        country = general['country_name']
                        city = general['city']
                        if city is None:
                            location = country
                        else:
                            location = city + ',' + country
                    except Exception as e:
                        location = 'Exception:' + str(e)
                        print(location)

                    try:
                        asn = general['asn']
                    except Exception as e:
                        asn = 'Exception:' + str(e)
                        print(asn)

                    ipv4_otx = [ip, pulse_count, false_positive_str, validation_str, location, asn, str(tags_size) + " Related Tags: \n" + tags_str]
                else:
                    retry += 1
                    if retry < 3:
                        continue
                    else:
                        ipv4_otx = [ip, "status_code:" + str(status_code), "status_code:" + str(status_code), "status_code:" + str(status_code), "status_code:" + str(status_code), "status_code:" + str(status_code), "status_code:" + str(status_code)]
                print(ipv4_otx)
                break
            except Exception as e:
                retry += 1
                if retry < 3:
                    continue
                else:
                    ipv4_otx = [ip, "Exception:" + str(e), "Exception:" + str(e), "Exception:" + str(e), "Exception:" + str(e), "Exception:" + str(e), "Exception:" + str(e)]
                    print(ipv4_otx)
                    break
        return ipv4_otx

    """
    Get the threat intelligence of IPv4 addresses in a list from OTX
    """
    def get_ipv4_list_otx(self, ip_list: list):
        otx_list = []
        size = len(ip_list)
        i = 0
        for ip in ip_list:
            i += 1
            print('Getting the OTX of ' + str(i) + "/" + str(size) + " IPv4")
            ip_otx = self.get_ipv4_otx(ip)
            otx_list.append(ip_otx)
        return otx_list

    """
    Export the threat intelligence of IPv4 addresses from OTX to a .csv file 
    """
    def export_ipv4_otx_csv(self, ip_otx_list: list):
        df = pd.DataFrame(ip_otx_list, columns=list(['IP', 'Pulse', 'False Positive', 'Validation', 'Location', 'ASN', 'Related Tags']))
        file_time = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        df.to_csv("IPv4_OTX_" + str(file_time) + ".csv", index=False)


if __name__ == '__main__':
    otx = OTX()
    ipv4_list = otx.get_ipv4_list()
    ipv4_otx_list = otx.get_ipv4_list_otx(ipv4_list)
    otx.export_ipv4_otx_csv(ipv4_otx_list)
