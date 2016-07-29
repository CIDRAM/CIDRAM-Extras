## **What is CIDRAM?**

CIDRAM (Classless Inter-Domain Routing Access Manager) is a PHP script designed to protect websites by blocking requests originating from IP addresses regarded as being sources of undesirable traffic, including (but not limited to) traffic from non-human access endpoints, cloud services, spambots, scrapers, etc. It does this by calculating the possible CIDRs of the IP addresses supplied from inbound requests and then attempting to match these possible CIDRs against its signature files (these signature files contain lists of CIDRs of IP addresses regarded as being sources of undesirable traffic); If matches are found, the requests are blocked.

## **What's this repository for?**

This repository, "__[CIDRAM-Extras](https://github.com/Maikuolan/CIDRAM-Extras)__", is a repository for any extras for CIDRAM that don't belong in the __[core CIDRAM repository](https://github.com/Maikuolan/CIDRAM)__.

*This file, "README.md", last edited: 29th July 2016 (2016.07.29).*
