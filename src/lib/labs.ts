// Troubleshooting labs: a real-world symptom, the packet capture of what happened,
// and a diagnosis question. Every lab replays an existing lesson scenario as evidence.

export interface T { en: string; hinglish: string }

export interface Lab {
  id: string;
  title: T;
  symptom: T;
  lesson: string;
  scenario: string;
  level: 1 | 2 | 3;
  question: T;
  options: T[];
  answer: number;
  hints: T[];
  explain: T;
}

export const LABS: Lab[] = [
  {
    id: "no-ip-address",
    title: { en: "Connected to Wi‑Fi, but no internet", hinglish: "Wi‑Fi connected hai, par internet nahi" },
    symptom: {
      en: "A student's laptop shows “Connected, no internet”. ipconfig shows the address 169.254.37.112.",
      hinglish: "Ek student ke laptop pe “Connected, no internet” aa raha hai. ipconfig mein address 169.254.37.112 dikh raha hai.",
    },
    lesson: "dhcp", scenario: "no-server", level: 1,
    question: { en: "What went wrong?", hinglish: "Gadbad kahan hui?" },
    options: [
      { en: "The DNS server is down", hinglish: "DNS server band hai" },
      { en: "No DHCP server answered, so the laptop gave itself a link-local address", hinglish: "Kisi DHCP server ne jawab nahi diya, isliye laptop ne khud ko link-local address de diya" },
      { en: "The website blocked the laptop", hinglish: "Website ne laptop ko block kar diya" },
      { en: "The Wi‑Fi password is wrong", hinglish: "Wi‑Fi password galat hai" },
    ],
    answer: 1,
    hints: [
      { en: "Look at what the laptop sends again and again, and whether anything comes back.", hinglish: "Dekho laptop baar-baar kya bhej raha hai, aur kya koi jawab aata hai." },
      { en: "169.254.x.x is the range a computer picks for itself (APIPA).", hinglish: "169.254.x.x woh range hai jo computer khud ke liye chunta hai (APIPA)." },
    ],
    explain: {
      en: "The laptop broadcast DHCP DISCOVER several times with growing gaps and never got an OFFER. With no server, it self-assigned 169.254.x.x after an ARP probe. That address only works on the local link, so there is no gateway and no internet. Fix: check the router's DHCP server or the cable/VLAN to it.",
      hinglish: "Laptop ne kai baar DHCP DISCOVER broadcast kiya, har baar thoda ruk ke, par koi OFFER nahi aaya. Server na milne pe usne ARP probe ke baad khud ko 169.254.x.x de diya. Yeh address sirf local link pe chalta hai, isliye na gateway hai na internet. Fix: router ka DHCP server ya uska cable/VLAN check karo.",
    },
  },
  {
    id: "site-not-found",
    title: { en: "“This site can't be reached”", hinglish: "“This site can't be reached”" },
    symptom: { en: "The browser shows DNS_PROBE_FINISHED_NXDOMAIN for a site a friend just shared.", hinglish: "Dost ne jo site share ki, browser us pe DNS_PROBE_FINISHED_NXDOMAIN dikha raha hai." },
    lesson: "dns", scenario: "nxdomain", level: 1,
    question: { en: "Which answer explains the error?", hinglish: "Kaunsa jawab error ko samjhata hai?" },
    options: [
      { en: "The server is overloaded", hinglish: "Server pe bahut load hai" },
      { en: "The TCP handshake failed", hinglish: "TCP handshake fail ho gaya" },
      { en: "The name does not exist in DNS (likely a typo), so there is no IP to connect to", hinglish: "Yeh naam DNS mein exist hi nahi karta (shayad typo), toh connect karne ke liye koi IP nahi hai" },
      { en: "The certificate has expired", hinglish: "Certificate expire ho gaya" },
    ],
    answer: 2,
    hints: [
      { en: "Is there any TCP packet at all in the capture?", hinglish: "Kya capture mein koi TCP packet hai bhi?" },
      { en: "Open the DNS response and read the flags field.", hinglish: "DNS response kholo aur flags field padho." },
    ],
    explain: {
      en: "The DNS response carries rcode NXDOMAIN: the authoritative servers say the name doesn't exist. The browser never gets an IP address, so it never even starts TCP. Fix: check the spelling.",
      hinglish: "DNS response mein rcode NXDOMAIN hai: authoritative servers keh rahe hain ki yeh naam exist nahi karta. Browser ko IP address milta hi nahi, toh TCP shuru hi nahi hota. Fix: spelling check karo.",
    },
  },
  {
    id: "connection-refused",
    title: { en: "curl: Connection refused", hinglish: "curl: Connection refused" },
    symptom: { en: "A developer runs curl http://203.0.113.10:8080 and gets “Connection refused” instantly.", hinglish: "Ek developer curl http://203.0.113.10:8080 chalata hai aur turant “Connection refused” aata hai." },
    lesson: "tcp", scenario: "closed-port", level: 1,
    question: { en: "What does the capture prove?", hinglish: "Capture kya saabit karta hai?" },
    options: [
      { en: "A firewall silently dropped the SYN", hinglish: "Firewall ne SYN chupchaap drop kar diya" },
      { en: "The server is reachable, but nothing is listening on port 8080, so it answered RST", hinglish: "Server tak pahunch rahe hain, par port 8080 pe koi sun nahi raha, isliye RST aaya" },
      { en: "DNS returned the wrong address", hinglish: "DNS ne galat address diya" },
      { en: "The packet's TTL ran out", hinglish: "Packet ka TTL khatam ho gaya" },
    ],
    answer: 1,
    hints: [
      { en: "How long did the answer take, and which flags does it carry?", hinglish: "Jawab kitni der mein aaya, aur usme kaunse flags hain?" },
      { en: "A firewall that drops packets sends nothing back at all.", hinglish: "Jo firewall packet drop karta hai woh kuch bhi wapas nahi bhejta." },
    ],
    explain: {
      en: "The SYN got an immediate RST, ACK from the server itself. A reply means the host is up and reachable; RST means no program is bound to that port. A firewall drop would look like silence and retries ending in a timeout. Fix: start the service or use the right port.",
      hinglish: "SYN ka turant RST, ACK server se hi aaya. Jawab aaya matlab host on hai aur reachable hai; RST matlab us port pe koi program nahi sun raha. Firewall drop hota toh bilkul silence hota aur retries ke baad timeout. Fix: service start karo ya sahi port use karo.",
    },
  },
  {
    id: "routing-loop",
    title: { en: "Requests time out, traceroute repeats itself", hinglish: "Requests time out, traceroute baar-baar same routers" },
    symptom: { en: "A server is unreachable. traceroute shows the same two routers alternating until the hop limit.", hinglish: "Ek server tak nahi pahunch pa rahe. traceroute mein same do routers baar-baar aa rahe hain, hop limit tak." },
    lesson: "ip", scenario: "loop", level: 2,
    question: { en: "What is happening to the packets?", hinglish: "Packets ke saath kya ho raha hai?" },
    options: [
      { en: "They are encrypted and can't be read", hinglish: "Woh encrypted hain aur padhe nahi ja sakte" },
      { en: "They bounce between two routers until the TTL reaches zero (a routing loop)", hinglish: "Woh do routers ke beech ghoomte rehte hain jab tak TTL zero na ho jaaye (routing loop)" },
      { en: "The destination is too far away", hinglish: "Destination bahut door hai" },
      { en: "ARP failed on the laptop", hinglish: "Laptop pe ARP fail ho gaya" },
    ],
    answer: 1,
    hints: [
      { en: "Watch the TTL field as the packet moves.", hinglish: "Packet chalne ke saath TTL field dekho." },
      { en: "Which ICMP message finally comes back, and from where?", hinglish: "Aakhir mein kaunsa ICMP message aata hai, aur kahan se?" },
    ],
    explain: {
      en: "Two routers each think the other is the way to the destination, so the packet ping-pongs while every hop lowers TTL by one. At zero, a router drops it and sends ICMP Time Exceeded. TTL is what stops loops from lasting forever. Fix: correct the routing table on one of the routers.",
      hinglish: "Do routers dono sochte hain ki doosra hi destination ka raasta hai, isliye packet ping-pong hota rehta hai aur har hop TTL ek kam karta hai. Zero pe router use drop karke ICMP Time Exceeded bhejta hai. TTL hi loops ko hamesha chalne se rokta hai. Fix: kisi ek router ki routing table theek karo.",
    },
  },
  {
    id: "cert-expired",
    title: { en: "“Your connection is not private”", hinglish: "“Your connection is not private”" },
    symptom: { en: "Chrome shows NET::ERR_CERT_DATE_INVALID on the college portal this morning. Yesterday it worked.", hinglish: "Aaj subah college portal pe Chrome NET::ERR_CERT_DATE_INVALID dikha raha hai. Kal tak chal raha tha." },
    lesson: "tls", scenario: "expired", level: 2,
    question: { en: "Where does the connection break?", hinglish: "Connection kahan toot-ta hai?" },
    options: [
      { en: "During DNS lookup", hinglish: "DNS lookup ke time" },
      { en: "In the TLS handshake: the server's certificate is past its expiry date, so the client aborts with an alert", hinglish: "TLS handshake mein: server ka certificate expiry date paar kar chuka hai, toh client alert bhej ke band kar deta hai" },
      { en: "After the page loads", hinglish: "Page load hone ke baad" },
      { en: "In the TCP handshake", hinglish: "TCP handshake mein" },
    ],
    answer: 1,
    hints: [
      { en: "Find the last packet the client sends. What type of TLS record is it?", hinglish: "Client ka aakhri packet dhoondo. Woh kaunse type ka TLS record hai?" },
      { en: "TCP completed fine; look after the Server Hello.", hinglish: "TCP theek se complete hua; Server Hello ke baad dekho." },
    ],
    explain: {
      en: "TCP and the TLS hellos complete, but when the client checks the certificate's validity dates, it fails and sends a fatal alert (certificate_expired) and closes. No HTTP is ever sent. Fix: the site owner must renew the certificate; never click through on sites with passwords.",
      hinglish: "TCP aur TLS hellos poore hote hain, par jab client certificate ki validity dates check karta hai toh woh fail hota hai, client fatal alert (certificate_expired) bhejta hai aur connection band. HTTP kabhi bheja hi nahi jaata. Fix: site owner ko certificate renew karna hoga; password wali site pe warning ignore mat karo.",
    },
  },
  {
    id: "ftp-listing-hangs",
    title: { en: "FTP logs in, but the file list never arrives", hinglish: "FTP login ho jaata hai, par file list kabhi nahi aati" },
    symptom: { en: "Login succeeds, then LIST hangs and the server finally says “425 Can't open data connection”.", hinglish: "Login ho jaata hai, phir LIST atak jaata hai aur aakhir mein server bolta hai “425 Can't open data connection”." },
    lesson: "ftp", scenario: "active-nat", level: 2,
    question: { en: "Why can't the data connection open?", hinglish: "Data connection kyun nahi khul raha?" },
    options: [
      { en: "The password was wrong", hinglish: "Password galat tha" },
      { en: "Active mode: the server tries to connect back to the client's private address, and NAT/firewall blocks it", hinglish: "Active mode: server client ke private address pe wapas connect karne ki koshish karta hai, aur NAT/firewall use rok deta hai" },
      { en: "The file is too big", hinglish: "File bahut badi hai" },
      { en: "DNS is broken", hinglish: "DNS kharab hai" },
    ],
    answer: 1,
    hints: [
      { en: "Read the PORT command: which IP address does the client announce?", hinglish: "PORT command padho: client kaunsa IP address bata raha hai?" },
      { en: "Who opens the data connection in active mode?", hinglish: "Active mode mein data connection kaun kholta hai?" },
    ],
    explain: {
      en: "In active mode the client says “connect to me at this IP and port” and the server opens the data connection inward. The client sits behind NAT and announced a private 192.168.x.x address the server can't reach, so the server's SYNs go nowhere. Fix: use passive mode (PASV), where the client opens both connections, or better, SFTP.",
      hinglish: "Active mode mein client bolta hai “mujhse is IP aur port pe connect karo” aur server andar ki taraf data connection kholta hai. Client NAT ke peeche hai aur usne private 192.168.x.x address bataya jahan server pahunch hi nahi sakta, isliye server ke SYN kahin nahi jaate. Fix: passive mode (PASV) use karo, jisme dono connection client kholta hai, ya behtar SFTP.",
    },
  },
  {
    id: "big-packets-vanish",
    title: { en: "Ping works, big transfers stall", hinglish: "Ping chalta hai, badi files atak jaati hain" },
    symptom: { en: "Between two data-centre VMs, ping and SSH login work, but copying a large file freezes.", hinglish: "Do data-centre VMs ke beech ping aur SSH login chal rahe hain, par badi file copy karte hi sab ruk jaata hai." },
    lesson: "vxlan", scenario: "mtu", level: 3,
    question: { en: "What's the most likely cause?", hinglish: "Sabse zyaada sambhav wajah kya hai?" },
    options: [
      { en: "The disk is full", hinglish: "Disk full hai" },
      { en: "The overlay adds ~50 bytes of headers, so full-size packets exceed the underlay MTU and are dropped", hinglish: "Overlay ~50 bytes headers jodta hai, isliye full-size packets underlay MTU se bade ho jaate hain aur drop hote hain" },
      { en: "SSH encryption is too slow", hinglish: "SSH encryption bahut slow hai" },
      { en: "The VMs have the same MAC address", hinglish: "VMs ka same MAC address hai" },
    ],
    answer: 1,
    hints: [
      { en: "Compare the sizes of the packets that get through with the ones that don't.", hinglish: "Jo packets pahunch rahe hain aur jo nahi, unke size compare karo." },
      { en: "Count the outer headers: Ethernet + IP + UDP + VXLAN.", hinglish: "Bahar ke headers gino: Ethernet + IP + UDP + VXLAN." },
    ],
    explain: {
      en: "Small packets fit even with the 50-byte VXLAN wrapper. A 1500-byte inner packet becomes 1550 bytes outside, larger than the 1500-byte MTU of the physical network, so it is dropped. Fix: raise the underlay MTU (e.g. 1600 or jumbo frames) or lower the VM MTU to 1450.",
      hinglish: "Chhote packets 50-byte VXLAN wrapper ke saath bhi fit ho jaate hain. 1500-byte ka andar wala packet bahar 1550 bytes ka ban jaata hai, jo physical network ke 1500-byte MTU se bada hai, toh drop ho jaata hai. Fix: underlay MTU badhao (jaise 1600 ya jumbo frames) ya VM ka MTU 1450 karo.",
    },
  },
  {
    id: "wifi-wont-join",
    title: { en: "Phone won't join the Wi‑Fi", hinglish: "Phone Wi‑Fi join nahi kar raha" },
    symptom: { en: "The phone sees the network, tries to connect, then says “Couldn't connect” and drops.", hinglish: "Phone ko network dikhta hai, connect karne ki koshish karta hai, phir “Couldn't connect” bol ke chhod deta hai." },
    lesson: "wifi", scenario: "wrong-password", level: 2,
    question: { en: "At which point does joining fail?", hinglish: "Join kis point pe fail hota hai?" },
    options: [
      { en: "The phone can't hear the beacons", hinglish: "Phone ko beacons sunai nahi dete" },
      { en: "In the 4-way handshake: message 2's MIC doesn't match because the password-derived key is different, so the AP deauthenticates", hinglish: "4-way handshake mein: message 2 ka MIC match nahi karta kyunki password se bani key alag hai, isliye AP deauth kar deta hai" },
      { en: "DHCP gave a wrong address", hinglish: "DHCP ne galat address diya" },
      { en: "DNS failed", hinglish: "DNS fail ho gaya" },
    ],
    answer: 1,
    hints: [
      { en: "Authentication and association succeed. Look at the EAPOL frames.", hinglish: "Authentication aur association ho jaate hain. EAPOL frames dekho." },
      { en: "The password never travels on the air. How does the AP still know it's wrong?", hinglish: "Password kabhi hawa mein nahi jaata. Phir bhi AP ko kaise pata chalta hai ki galat hai?" },
    ],
    explain: {
      en: "Both sides derive keys from the password. With a wrong password the phone computes a different key, so the integrity check (MIC) on handshake message 2 fails at the access point, which ends the attempt with a deauthentication. Fix: re-enter the password.",
      hinglish: "Dono sides password se keys banate hain. Galat password se phone alag key banata hai, isliye handshake message 2 ka integrity check (MIC) access point pe fail hota hai, aur AP deauthentication bhej ke koshish khatam kar deta hai. Fix: password dobara daalo.",
    },
  },
  {
    id: "slow-page-lossy",
    title: { en: "One slow image blocks the whole page", hinglish: "Ek slow image poore page ko rok deti hai" },
    symptom: { en: "On a lossy mobile network, every image on an HTTP/2 site freezes at the same moment, then all appear together.", hinglish: "Lossy mobile network pe HTTP/2 site ki saari images ek saath ruk jaati hain, phir sab ek saath aati hain." },
    lesson: "http2", scenario: "hol", level: 3,
    question: { en: "Why do unrelated streams stall together?", hinglish: "Alag-alag streams ek saath kyun rukti hain?" },
    options: [
      { en: "The server sends images one by one on purpose", hinglish: "Server jaan-boojh ke images ek-ek karke bhejta hai" },
      { en: "One lost TCP segment holds back all later bytes, and every HTTP/2 stream shares that one TCP connection", hinglish: "Ek lost TCP segment baad ke saare bytes rok deta hai, aur saari HTTP/2 streams usi ek TCP connection pe hain" },
      { en: "The images are too large", hinglish: "Images bahut badi hain" },
      { en: "DNS is slow", hinglish: "DNS slow hai" },
    ],
    answer: 1,
    hints: [
      { en: "Find the lost packet. Which streams' frames came after it?", hinglish: "Lost packet dhoondo. Kaunsi streams ke frames uske baad aaye?" },
      { en: "TCP hands data to the app strictly in order.", hinglish: "TCP data app ko sirf order mein deta hai." },
    ],
    explain: {
      en: "HTTP/2 multiplexes many streams over one TCP connection. TCP must deliver bytes in order, so one missing segment blocks every later byte, including frames of other streams that already arrived. This is TCP head-of-line blocking; HTTP/3 over QUIC fixes it with independent streams.",
      hinglish: "HTTP/2 ek TCP connection pe kai streams chalata hai. TCP ko bytes order mein dene hote hain, isliye ek missing segment baad ke saare bytes rok deta hai, doosri streams ke frames bhi jo pahunch chuke hain. Ise TCP head-of-line blocking kehte hain; HTTP/3 (QUIC) alag-alag streams se ise theek karta hai.",
    },
  },
  {
    id: "bad-gateway",
    title: { en: "502 Bad Gateway", hinglish: "502 Bad Gateway" },
    symptom: { en: "The shop website shows “502 Bad Gateway” from nginx. The nginx server itself is up.", hinglish: "Shop website pe nginx se “502 Bad Gateway” aa raha hai. Nginx server khud chal raha hai." },
    lesson: "reverse", scenario: "bad-gateway", level: 2,
    question: { en: "Who is failing?", hinglish: "Fail kaun ho raha hai?" },
    options: [
      { en: "The visitor's browser", hinglish: "Visitor ka browser" },
      { en: "The reverse proxy can't get an answer from any backend server", hinglish: "Reverse proxy ko kisi bhi backend server se jawab nahi mil raha" },
      { en: "The visitor's DNS", hinglish: "Visitor ka DNS" },
      { en: "The TLS certificate", hinglish: "TLS certificate" },
    ],
    answer: 1,
    hints: [
      { en: "The proxy talks to two networks. Look at the packets on the backend side.", hinglish: "Proxy do networks se baat karta hai. Backend side ke packets dekho." },
      { en: "What do the backends answer to the proxy's SYN?", hinglish: "Proxy ke SYN ka backends kya jawab dete hain?" },
    ],
    explain: {
      en: "The client's TLS connection to the proxy works fine. The proxy then tries both backends and gets refused (RST) by each, so it has nothing to forward and generates a 502 itself. The problem is behind the proxy. Fix: restart or repair the app servers; health checks should alert you first.",
      hinglish: "Client ka proxy tak TLS connection theek chal raha hai. Phir proxy dono backends try karta hai aur dono se refuse (RST) milta hai, toh aage bhejne ko kuch nahi, isliye proxy khud 502 banata hai. Problem proxy ke peeche hai. Fix: app servers restart ya theek karo; health checks pehle hi alert kar dete.",
    },
  },
  {
    id: "upi-pending",
    title: { en: "Money debited, shop says not received", hinglish: "Paise kat gaye, dukaan bolti hai mile nahi" },
    symptom: { en: "A ₹250 UPI payment shows “Pending”. The bank SMS says ₹250 debited, but the shopkeeper's app shows nothing.", hinglish: "₹250 ka UPI payment “Pending” dikha raha hai. Bank SMS mein ₹250 debit likha hai, par dukaandar ke app mein kuch nahi." },
    lesson: "upi", scenario: "pending", level: 1,
    question: { en: "What should the customer understand from the flow?", hinglish: "Flow dekh ke customer ko kya samajhna chahiye?" },
    options: [
      { en: "The money is lost forever", hinglish: "Paise hamesha ke liye gaye" },
      { en: "Pay again right away", hinglish: "Turant dobara pay karo" },
      { en: "The credit leg timed out; the status check finds no credit and the debit is reversed automatically", hinglish: "Credit wala hissa time out ho gaya; status check mein credit nahi mila, toh debit apne aap reverse ho jaata hai" },
      { en: "The UPI PIN was wrong", hinglish: "UPI PIN galat tha" },
    ],
    answer: 2,
    hints: [
      { en: "Which leg of the payment never got its response?", hinglish: "Payment ke kis hisse ka response kabhi nahi aaya?" },
      { en: "Look for the status-check request after the timeout.", hinglish: "Timeout ke baad status-check request dhoondo." },
    ],
    explain: {
      en: "The debit from the payer's bank succeeded, but the credit to the payee's bank timed out, so the switch can't confirm success and marks it pending. A status check (ReqChkTxn) shows no credit, so the debit is reversed. Paying again immediately risks paying twice; wait for the reversal or the final status.",
      hinglish: "Payer ke bank se debit ho gaya, par payee ke bank mein credit time out ho gaya, toh switch success confirm nahi kar sakta aur pending dikhata hai. Status check (ReqChkTxn) mein credit nahi milta, toh debit reverse ho jaata hai. Turant dobara pay karoge toh do baar kat sakte hain; reversal ya final status ka wait karo.",
    },
  },
  {
    id: "gateway-mac-changed",
    title: { en: "Everyone's internet suddenly slow on the lab LAN", hinglish: "Lab LAN pe sabka internet achanak slow" },
    symptom: { en: "In a computer lab, `arp -a` on one PC shows the router's IP with a MAC that belongs to another student's laptop.", hinglish: "Computer lab mein ek PC pe `arp -a` chalane pe router ke IP ke saath ek doosre student ke laptop ka MAC dikh raha hai." },
    lesson: "arp", scenario: "spoofing", level: 2,
    question: { en: "What is going on?", hinglish: "Kya chal raha hai?" },
    options: [
      { en: "The router changed its network card", hinglish: "Router ne apna network card badal liya" },
      { en: "ARP spoofing: a machine keeps sending fake ARP replies claiming the router's IP, so traffic flows through it", hinglish: "ARP spoofing: ek machine baar-baar fake ARP reply bhej rahi hai ki router ka IP uska hai, isliye traffic usse ho ke jaata hai" },
      { en: "DHCP gave two PCs the same IP", hinglish: "DHCP ne do PCs ko same IP de diya" },
      { en: "The switch is broken", hinglish: "Switch kharab hai" },
    ],
    answer: 1,
    hints: [
      { en: "Look for ARP replies nobody asked for.", hinglish: "Aise ARP replies dhoondo jo kisi ne maange hi nahi." },
      { en: "Compare the sender MAC in those replies with the real router's MAC.", hinglish: "Un replies ka sender MAC asli router ke MAC se milao." },
    ],
    explain: {
      en: "ARP has no authentication, so any host can send unsolicited replies saying “192.168.1.1 is at my MAC”. Victims update their cache and send gateway traffic to the attacker, who can read or slow it. Defence: Dynamic ARP Inspection on the switch (checks replies against DHCP snooping), static entries for the gateway, and always use HTTPS.",
      hinglish: "ARP mein koi authentication nahi hota, isliye koi bhi host bina maange reply bhej sakta hai ki “192.168.1.1 mere MAC pe hai”. Victims apna cache update kar lete hain aur gateway ka traffic attacker ko bhejte hain, jo use padh ya slow kar sakta hai. Bachav: switch pe Dynamic ARP Inspection (DHCP snooping se replies check karta hai), gateway ki static entry, aur hamesha HTTPS.",
    },
  },
];

export const getLab = (id: string) => LABS.find((l) => l.id === id);
