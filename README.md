## Project Description

#### 🔐 What brute force looks like in logs

Brute force attacks appear as many rapid failed login attempts from the same IP, often targeting common usernames (root, admin, test).
Instead of one or two failures, attackers generate clusters of attempts within seconds.

#### ⏱ Why time bursts matter

Single failed logins happen naturally.
High-frequency attempts within short time windows strongly indicate automation.

By detecting bursts within 60 seconds, the tool distinguishes real attacks from normal user mistakes.

#### 📊 What insights my tool generates

• identifies IPs performing brute force attacks
• measures attack intensity using time-window clustering
• highlights most targeted usernames
• ranks attackers by severity
• flags suspicious behavior automatically


This project simulates how security teams analyze authentication logs to detect real-world intrusion attempts using behavioral patterns rather than simple counts.
