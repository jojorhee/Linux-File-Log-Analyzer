import re
from dateutil import parser
from collections import Counter


file_path = "logs/auth.log"

logs = []
failed_logs = 0
dates = []
triggers = [r"\bInvalid user\b"]


def parse(file_path):
    global failed_logs
    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                
                if re.findall(triggers[0], line):
                    logs.append(line.split("]: ")[1])

                    # parse dates   
                    date = line[:15]
                    dates.append(date)         

                    failed_logs += 1 # now, the auth.log just shows all failed login attempts so not much to do           


    except FileNotFoundError:  
        print("File not found")
    except Exception as e:
        print(f"Error: {e}")

    #print(logs[6767])
    #print(logs[6767][13:])
    
def analyze(logs, dates):
    print("Log Analysis Summary")
    print(f"Time range analyzed: {dates[0]} - {dates[-1]}")
    print(f"Total number of login attempts: {len(logs)}")
    print(f"Total number of failed login attempts: {failed_logs}")
    print("-----------------------------------------------------")

    if failed_logs == 0:
        print("All good for now!")
    else:
        print("\033[1mAlerts Triggered\033[0m")
        pattern = re.compile(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

        # list each user, their ip address and how many times they attempted to log in
        ip_list = []
        username_pattern = re.compile("Invalid user (\w+)")
        user_list = []
        timeb_list = []
        timeb_dict = {}
        
        for log in range(len(logs)):
            name_match = username_pattern.search(logs[log])
            match = pattern.search(logs[log])
            if match:
                ip_list.append(match.group())
                timeb_list.append([match.group(), dates[log]])
            # track the usernames attacked!
            if name_match:
                user_list.append(name_match.group(1))

        ips = Counter(ip_list)
        dangerous_ips = ips.most_common()
        high_risks = []
        high_c = 3
        med_risks = []
        med_c = 3
        low_risks = []
        low_c = 3

        for ip in range(len(dangerous_ips)):
            if dangerous_ips[ip][1] >= 100 and high_c >= 0:
                high_risks.append(dangerous_ips[ip])
                high_c -= 1
            elif dangerous_ips[ip][1] >= 50 and med_c >= 0:
                med_risks.append(dangerous_ips[ip])
                med_c -= 1
            elif dangerous_ips[ip][1] >= 10 and low_c >= 0:
                low_risks.append(dangerous_ips[ip])
                low_c -= 1

        print("\033[1mHigh Risks!\033[0m")
        for ip in high_risks:
            print(f"IP Address {ip[0]}: {ip[1]} failed login attempts!")
        print("\033[1mMedium Risks!\033[0m")
        for ip in med_risks:
            print(f"IP Address {ip[0]}: {ip[1]} failed login attempts!")
        print("\033[1mLow Risks!\033[0m")
        for ip in low_risks:
            print(f"IP Address {ip[0]}: {ip[1]} failed login attempts!")

        print("-------------------------------")
        print("\033[1mTop 10 Targeted Accounts & which IPs attack which users\033[0m")
        print("\033[1mWill do second part later\033[0m")

        usernames = Counter(user_list)
        targeted_users = usernames.most_common()
        #print(usernames)

        # for now, we will do top 10 targeted accounts
        for i in range(10):
            print(f"{targeted_users[i][0]} - {targeted_users[i][1]} failed attempts")

        print("----------------------------")
        print("\033[1mTime Window Bursts!\033[0m")

        
        #print(timeb_list[11])
        #['218.26.11.118', 'Nov 30 17:48:08']
        #['218.26.11.118', datetime.datetime(2026, 11, 30, 17, 48, 8)]

        # TIME BURST CODE
        for entry in timeb_list:
            entry[1] = parser.parse(entry[1])

        ips = sorted(ips)
        times = []
        for ip in ips:
            for entry in timeb_list:
                if ip in entry:
                    times.append(entry[1])
                timeb_dict.update({ip:times})
            times = []

        counts = {}
        for ip, times in timeb_dict.items():
            alerts = 0
            alerts_list = []
            counter = 0
            for time in range(len(times)):
                window = times[0]
                t = times[time]
                
                if t != window and (t - window).seconds < 60:
                    alerts += 1
                else:
                    alerts_list.append(alerts)
                    alerts = 0
                    if time < len(times) - 1:
                        window = times[time + 1] 
                counter += 1

            if max(alerts_list) < 1: 
                counts.update({ip: 1})
            else:
                counts.update({ip: max(alerts_list)})
            alerts = 0
            alerts_list = []

        counts = dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))
        #print(counts)

        
        for ip, occurences in counts.items():
            if occurences >= 20:
                print(f"Brute force attack by {ip}: {occurences} attempts within a minute!")
            elif occurences >= 5:
                print(f"Heavy attack by {ip}: {occurences} attempts within a minute!")




parse(file_path)

analyze(logs, dates)
