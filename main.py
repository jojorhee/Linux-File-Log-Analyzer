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
        
        for log in range(len(logs)):
            name_match = username_pattern.search(logs[log])
            match = pattern.search(logs[log])
            if match:
                ip_list.append(match.group())
                timeb_list.append([match.group(), dates[log]])
            # track the usernames attacked!
            if name_match:
                user_list.append(name_match.group(1))

        print("Bruh")
        print(timeb_list[0])

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
        print("Time Window Bursts!")

        

        for date in dates:
            date = parser.parse(date)

        print(dates[0])





parse(file_path)

analyze(logs, dates)
