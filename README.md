## 1. Vulnerabilities and Malware

### 1.1 National Vulnerability Database

A vulnerability in the Google Chrome web browser was reported to the National Vulnerability
Database (NVD) on the 17th of February 2017 affecting the browsers displaying of
internationalized domain names (IDNs) in its address bar, or Omnibar.

The vulnerability allowed an attacker to spoof an English domain name using Punycode - a means
to represent Unicode characters using the limited subset of ASCII characters used for domains on
the Internet.

This attack is known as an IDN homograph attack.

This specific vulnerability was assigned CVE-2017-5015, and is documented by the NVD as
affected versions of Chrome prior to 56 on Linux, Windows, Mac, and Android. However, on the
14th of April 2017, Xudong Zheng reported a similar vulnerability affecting all versions of Google
Chrome released to that date.

Xudong registered the domain xn--80ak6aa92e.com, gave it the standard www subdomain, and
requested an HTTPS certificate from certificate authority Let’s Encrypt.

Let’s Encrypt is a well known provider of free HTTPS certificates, who provides certificates on an
automated basis to individuals who can prove domain ownership (by serving content or creating a
DNS entry). Let’s Encrypt do not manually validate domains, or check them for malicious intent.

In versions of Google Chrome below 58 (58.0.3029.81, specifically) the URL `https://www.xn--
80ak6aa92e.com` rendered as `https://www.apple.com` in the address bar. Google assigned this
specific vulnerability the identifier CVE-2017-5060. Google paid Xudong $2,000 USD for reporting
this vulnerability, and Haosheng Wang $2,000 USD for CVE-2017-5015.

**i.** CVE-2017-5015 received a CVSS v3 Base Score of 6.5 (Medium) from the NVD, and CVE-2017-
5060 also received a score of Medium from Google.

**ii.** CVE-2017-5015 received an Impact Score of 3.6 from the NVD.

**iii.** Two valid purposes of using the CVSS scoring system are;

1. The system is a standardised means to categorise vulnerabilities and prioritise their
patching.

2. The system is an evidence-based empirical means to categorise vulnerabilities
independant to media and individual speculation and sensationalism.

**iv.** CVE-2017-5015 was patched in Google Chrome release 56.0.2924.76, and CVE-2017-5060
was patched in Google Chrome release 58.0.3029.81.

**v.** This set of vulnerabilities are very specific and were difficult to mitigate even for the most novice
of users.

The Australian Signals Directorate (ASD) publishes strategies to mitigate vulnerabilities. From their
strategies, the following would have acted to mitigate an IDN homograph attack;

* **Patch applications** - This would have been the most helpful in mitigating any attacks that resulted from these
vulnerabilities. In both cases Google updated its browser in a timely manner, and the
updates resolved the issue.

* **Antivirus software with up-to-date signatures** - This would have been less helpful, but could have potentially mitigated an attack. Antivirus software often prohibits access to malicious domains and IP addresses, and an antivirus
software could have potentially discovered a domain being used to conduct an IDN
homograph attack before a user visited the site and blocked access to it. As with most blacklisting strategies, this solution is limited because it requires the antivirus
software become aware of the attack before a user is affected.

* **User education** - User education would have been highly limited in this scenario. This is because, in the
example of CVE-2017-5060, the Punycode URL rendered as `https://www.apple.com`
exactly. More advanced users may have noticed that the certificate was issued to `www.xn--
80ak6aa92e.com`, however.

**References**

* https://nvd.nist.gov/vuln/detail/CVE-2017-5015
* https://www.xudongz.com/blog/2017/idn-phishing/
* https://letsencrypt.org/getting-started/
* https://www.asd.gov.au/infosec/top-mitigations/mitigations-2017-table.htm
* https://chromereleases.googleblog.com/2017/04/stable-channel-update-for-desktop.html
* https://chromereleases.googleblog.com/2017/01/stable-channel-update-for-desktop.html

### 1.2 Antivirus company evaluation

On May 12th 2017, a ransomware threat that was referred to as WannaCry, was observed in
Europe.

It affected several large-scale organisations and institutions on the continent, including the British
National Health Service (NHS).

This section will analyse the detection of WannaCry by several antivirus companies, in attempt to
display the ability of these companies to quickly respond to an emerging threat.
This analysis was performed three times from 10:37pm on the 12th of May 2017 Greenwich Mean
Time (GMT). All detection samples are logged in GMT.

Company | Name for *WannaCry* | Detection 12-05-2017 10:37pm | Detection 12-05-2017 11:13pm | Detection 13-05-2017 4:02am
--- | --- | :---: | :---: | :---:
Ad-Aware | Generic.Ransom.HydraCrypt.C8B435F4 | ✓ | ✓ | ✓
Avast | Win32:WanaCry-A [Trj] | ✓ | ✓ | ✓ 
AVG | Generic_r.SSZ | ✓ | ✓ | ✓ 
Avira | TR/FileCoder.724645\ | ✕ | ✕ | ✓ 
AVware | | ✕ | ✕ | ✕ 
BitDefender | Trojan.Ransom.WannaCryptor.D | ✓ | ✓ | ✓
ClamAV | | ✕ | ✕ | ✕ 
Comodo | UnclassifiedMalware | ✓ | ✓ | ✓ 
Endgame | | ✕ | ✕ | ✕ 
ESET-NOD32 | Win32/Filecoder.WannaCryptor.D | ✓ | ✓ | ✓
F-Secure | Generic.Ransom.HydraCrypt.C8B435F4 | ✓ | ✓ | ✓
Kaspersky | Trojan-Ransom.Win32.Wanna.c | ✓ | ✓ | ✓
Malwarebytes | Ransom.WanaCrypt0r | ✓ | ✓ | ✓
McAfee | Artemis!7BF2B57F2A20 | ✓ | ✓ | ✓
Microsoft | Ransom:Win32/WannaCrypt | ✓ | ✓ | ✓
NANO-Antivirus | | ✕ | ✕ | ✕ 
Panda | Trj/RansomCrypt.K | ✓ | ✓ | ✓
Sophos | Troj/Wanna-D | ✕ | ✕ | ✓
SUPER AntiSpyware | | ✕ | ✕ | ✕ 
Symantec | ML.Attribute.HighConfidence | ✓ | ✓ | ✓
TrendMicro | RANSOM_WCRY.I | ✓ | ✓ | ✓
VIPRE | | ✕ | ✕ | ✕
Webroot | W32.Ransom.Wannacry | ✓ | ✓ | ✓
ZoneAlarm | Trojan-Ransom.Win32.Wanna.c | ✓ | ✓ | ✓
Zoner | | ✕ | ✕ | ✕ 

Using Google Trends, the absolute first international searches for WannaCry via Google started on
12-05-2017 10:00am GMT.
