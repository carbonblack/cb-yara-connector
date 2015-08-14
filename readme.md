# Using YARA with Carbon Black

## Requires:
- Carbon Black 4.2+
- yara-python: http://plusvic.github.io/yara/
- a set of yara rules

A sample set of yara rules from [Malware Config](http://malwareconfig.com/) is included in the rules/ directory.

## Overview

[Yara](http://plusvic.github.io/yara/) is the linga franca of malware analysts. 
With a robust language to define byte strings and clean, well-designed interfaces, 
many IR and security operations shops keep the results of their analysis in a local
repository of yara rules.

However, monitoring activity across your network for matches to your yara rules is 
difficult.  If possible at all, it usually involves infrequent, time-consuming scans.  
Since Carbon Black collects all executed binaries and has a robust API, it is possible
to configure your Carbon Black server to act as a "Yara Monitor" and automatically trigger
notification for any binary executed across your network matching any of your Yara rules.

