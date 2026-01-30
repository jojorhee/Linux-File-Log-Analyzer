import re
#import dateutil


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

    print(logs[0])
    
def analyze(logs, dates):
    print(f"Time range analyzed: {dates[0]} - {dates[-1]}")
    print(f"Total number of login attempts: {len(logs)}")
    print(f"Total number of failed login attempts: {failed_logs}")
    print("-----------------------------------------------------")

    print("Security Assessment:")

    # list each user, their ip address and how many times they attempted to log in




parse(file_path)

analyze(logs, dates)
