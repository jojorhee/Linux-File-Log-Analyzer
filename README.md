## Project Description

Overview

This project analyzes authentication logs to detect brute-force login attacks using time-based behavioral patterns rather than simple failure counts. By identifying rapid bursts of login attempts, it distinguishes automated attacks from normal user mistakes.

Problem

Authentication logs contain large volumes of failed logins, many of which are harmless.
Brute-force attacks, however, appear as clusters of attempts within short time windows from the same IP, often targeting common usernames.

Approach

The analyzer parses login-related events from authentication logs and, for each IP address:

groups attempts chronologically

applies a sliding time window to detect bursts

measures attack intensity

ranks suspicious IPs by severity

This mirrors techniques used in real security operations.

Insights Generated

Identifies brute-force attack sources

Measures attack intensity using time-window analysis

Highlights most targeted usernames

Filters normal login noise from real threats

Why Time Matters

Single failed logins are common.
Multiple attempts in under a minute strongly indicate automation.

By focusing on when attempts occur, the tool produces more accurate security insights.

Technologies

Python

Log parsing and data aggregation

Time-based burst analysis

Future Improvements

Detect successful logins after failed bursts

Visualize attack timelines

Support additional log formats
