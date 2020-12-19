# chrome-mal-ids
Listing of known malicious Google Chrome Extension IDs

This is something I personally use to try and keep up with malicious extensions reported publicly.  I did a bit of research and found there doesn't seem to be an easy way to keep up with the *installed* extensions after they've been pulled from the Chrome Web Store other than manually checking your extensions settings periodically.  To be honest, I've been lucky and have never installed a malicious extension so I'm not sure if the built-in security scans actually notify you automatically when an extension has been flagged or if you have to manually kick off the security scan.  (For me, it's manually run.)  So, there may be people like me that don't want to send all of their web browsing to Google which takes out the in-built "Enhanced Protection" from the local browser toolbox.  So I figured I'd setup an effort to try and find as many publicly available malicious extension IDs out there and aggregate them into a single downloadable text file so I could run a daily extension scan in the background.  I know how Herculean this effort is but, best I can tell, this type of information doesn't exist in a centralized format.  (I would think that VirusTotal might have these malicious extensions somewhere but haven't seen a way to get that info out yet...)  So this is def a work-in-progress and ultimately a fool's folly but I'm bored during this lockdown...

<b>*** This stuff should be used at your own risk.  If there's a malicious extension I've missed and you have it installed, I'm sorry about that but I'm not responsible for the miss.  There are no warranties / guarantees included with this effort.  It's just my best effort to keep up with the times.  YMMV. ***</b>

There's currently 550+ known malicious extension IDs in the aggregate.  A small bash script for Ubuntu / Debian distros has been provided to check the user's current Chrome extension directory and compare what's in there to the known compromised list. 

<b>Sources of the compromised list:</b> 

Dec 19, 2020<br>
Three million users installed 28 malicious Chrome or Edge extensions https://www.zdnet.com/article/three-million-users-installed-28-malicious-chrome-or-edge-extensions/ (Shouts to <a href=https://github.com/nycnewman>nycnewman</a> for messaging me about the breaking story!  Thank you!)

Because it took me awhile to find the exact extension IDs for this, I decided to post the IDs here for a bit to help other researchers get an easy text listing of the IoCs.

Extension IDs:
<pre>
mdpgppkombninhkfhaggckdmencplhmg
fgaapohcdolaiaijobecfleiohcfhdfb
iibnodnghffmdcebaglfgnfkgemcbchf
olkpikmlhoaojbbmmpejnimiglejmboe
bhfoemlllidnfefgkeaeocnageepbael
nilbfjdbacfdodpbdondbbkmoigehodg
eikbfklcjampfnmclhjeifbmfkpkfpbn
pfnmibjifkhhblmdmaocfohebdpfppkf
cgpbghdbejagejmciefmekcklikpoeel
klejifgmmnkgejbhgmpgajemhlnijlib
ceoldlgkhdbnnmojajjgfapagjccblib
mnafnfdagggclnaggnjajohakfbppaih
oknpgmaeedlbdichgaghebhiknmghffa
pcaaejaejpolbbchlmbdjfiggojefllp
lmcajpniijhhhpcnhleibgiehhicjlnk
lnocaphbapmclliacmbbggnfnjojbjgf
bhcpgfhiobcpokfpdahijhnipenkplji
dambkkeeabmnhelekdekfmabnckghdih
dgjmdlifhbljhmgkjbojeejmeeplapej
emechknidkghbpiodihlodkhnljplpjm
hajlccgbgjdcjaommiffaphjdndpjcio
dljdbmkffjijepjnkonndbdiakjfdcic
cjmpdadldchjmljhkigoeejegmghaabp
jlkfgpiicpnlbmmmpkpdjkkdolgomhmb
njdkgjbjmdceaibhngelkkloceihelle
phoehhafolaebdpimmbmlofmeibdkckp
pccfaccnfkjmdlkollpiaialndbieibj
fbhbpnjkpcdmcgcpfilooccjgemlkinn
</pre>

Oct 28, 2020<br>
Just fyi, the extensions used in the Kimsuky / Hidden Cobra <a href=https://us-cert.cisa.gov/ncas/alerts/aa20-301a>CISA alert AA20-302A</a> are already listed in current extension list.

Oct 21, 2020<br>
Adblockers installed 300,000 times are malicious and should be removed now  https://arstechnica.com/information-technology/2020/10/popular-chromium-ad-blockers-caught-stealing-user-data-and-accessing-accounts/

Oct 2, 2020<br>
Facebook sues two Chrome extension makers for scraping user data (2 extensions added) https://www.zdnet.com/article/facebook-sues-two-chrome-extension-makers-for-scraping-user-data/

Aug 4, 2020<br>
Cluster of 295 Chrome extensions caught hijacking Google and Bing search results  https://www.zdnet.com/article/cluster-of-295-chrome-extensions-caught-hijacking-google-and-bing-search-results/

Jun 19, 2020<br>
Found a extension that contains malware (2 extensions added) https://www.reddit.com/r/chrome/comments/hbpi7z/found_a_extension_that_contains_malware/

Jun 18, 2020<br>
Google removes 106 Chrome extensions for collecting sensitive user data https://www.zdnet.com/article/google-removes-106-chrome-extensions-for-collecting-sensitive-user-data/ https://awakesecurity.com/wp-content/uploads/2020/06/GalComm-Malicious-Chrome-Extensions-Appendix-B.txt

Apr 16, 2020<br>
49 malicious Chrome extensions caught pickpocketing crypto wallets  https://medium.com/mycrypto/discovering-fake-browser-extensions-that-target-users-of-ledger-trezor-mew-metamask-and-more-e281a2b80ff9

Feb 13, 2020<br>
Security Researchers Partner With Chrome To Take Down Browser Extension Fraud Network Affecting Millions of Users https://duo.com/labs/research/crxcavator-malvertising-2020

Jan 1, 2020<br>
Chrome extension caught stealing crypto-wallet private keys https://www.zdnet.com/article/chrome-extension-caught-stealing-crypto-wallet-private-keys/

Jul 22, 2019<br>
Malicious browser extensions are stealing personal information https://www.salon.com/2019/07/22/malicious-browser-extensions-are-stealing-personal-information/  https://dataspii.com/

May 10, 2018<br>
Nigelthorn Malware Abuses Chrome Extensions to Cryptomine and Steal Data https://blog.radware.com/security/2018/05/nigelthorn-malware-abuses-chrome-extensions/

Jan 18, 2018<br>
Malicious Chrome Extensions Enable Criminals to Impact Half a Million Users and Global Businesses https://atr-blog.gigamon.com/2018/01/18/malicious-chrome-extensions-enable-criminals-to-impact-half-a-million-users-and-global-businesses/

Aug 16, 2017<br>
Bank-fraud malware not detected by any AV hosted in Chrome Web Store. Twice https://arstechnica.com/information-technology/2017/08/bank-fraud-malware-not-detected-by-any-av-hosted-in-chrome-web-store-twice/

 
