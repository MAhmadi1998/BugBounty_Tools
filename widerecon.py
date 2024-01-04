import subprocess
import argparse
def banner():

    banner_ = """
 __          __             _            _____                      
 \ \        / /            (_)          |  __ \                     
  \ \  /\  / /_ _ _ __ _ __ _  ___  _ __| |__) |___  ___ ___  _ __  
   \ \/  \/ / _` | '__| '__| |/ _ \| '__|  _  // _ \/ __/ _ \| '_ \ 
    \  /\  / (_| | |  | |  | | (_) | |  | | \ \  __/ (_| (_) | | | |
     \/  \/ \__,_|_|  |_|  |_|\___/|_|  |_|  \_\___|\___\___/|_| |_|v1.0
                                                                                                                                     
    """
    print(banner_)




def Passive_Subdomains(domain):
    try:
        print("[*] Running Subfinder ...")
        subprocess.run(f"subfinder -d {domain} -silent > {domain}.subfinder.txt", shell=True, check=True)
    
           
        Command = f"""query=$(cat <<-END
        SELECT
            ci.NAME_VALUE
        FROM
            certificate_and_identities ci
        WHERE
            plainto_tsquery(\'certwatch\', \'{domain}\') @@ identities(ci.CERTIFICATE)
END
)
    echo \"$query\" | psql -t -h crt.sh -p 5432 -U guest certwatch | sed \'s/ //g\' | egrep \".*.\.{domain}\"| sed \'s/*\.//g\' | tr \'[:upper:]\' \'[:lower:]\' | sort -u """
        print("[*] Finding Subdomains from crtsh Database ...")
        subprocess.run(f"{Command} | grep -v \"*\" | sort -u > {domain}.crtsh.txt" , shell=True , check=True)
    
        print("[*] Searching in abuseipdb Database ...")
        subprocess.run(f"curl -s \"https://www.abuseipdb.com/whois/{domain}\" -H \"user-agent: Chrome\" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' > {domain}.abuseipdb.txt", shell=True , check=True)

        subprocess.run(f"cat {domain}.* | sort -u > {domain}.passivesubs.txt" , shell=True , check=True)


    except subprocess.CalledProcessError as e:
        print(f"[-] An Error occurred: {e}")

def DNS_BruteForce(domain):
    SetupCommands_Static = ["printf \"8.8.4.4\\n129.250.35.251\\n208.67.222.222\"  > resolvers.txt" , "curl -s https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -o best-dns-wordlist.txt" , "curl -s https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt -o 2m-subdomains.txt",
                     "cat best-dns-wordlist.txt 2m-subdomains.txt | sort -u > subdomains-assetnote-merged.txt" , "/root/crunch/crunch 1 4 abcdefghijklmnopqrstuvwxyz1234567890 > crunch.txt" , "cat crunch.txt subdomains-assetnote-merged.txt | sort -u > Static-Dns-Brute.txt"]

    for command in SetupCommands_Static:
        subprocess.run(command, shell=True, check=True)

    print("[*] Splitting list to 1M lines files ...")
    t = subprocess.run(f"split -l 1000000 Static-Dns-Brute.txt splitted.{domain}.; ls splitted*", shell=True , check=True , capture_output=True)
    Files = t.stdout.decode("utf-8").split("\n")
    print("[*] Starting Static DNS Bruteforce ...")
    i = 1
    for file in Files:
        if file != "":

            print(f"[*] Static Bruteforce on {file} ...")
            subprocess.run(f"shuffledns -w {file} -d {domain} -r ./resolvers.txt -m /usr/local/bin/massdns -o {domain}.staticbrute{i}.txt -silent" , shell=True , check=True)
            i = i + 1

    print("[+] Static Bruteforce is done.")
    subprocess.run(f"cat {domain}.staticbrute* > {domain}.staticbrute.txt" , shell=True , check=True)
        
    SetupCommands_Dynamic = ["curl -s https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -o altdns-words.txt" , "curl -s https://raw.githubusercontent.com/ProjectAnte/dnsgen/master/dnsgen/words.txt -o dnsgen-words.txt",
                             "cat altdns-words.txt dnsgen-words.txt | sort -u > words-merged.txt"]

    for command in SetupCommands_Dynamic:
        subprocess.run(command, shell=True, check=True)

    print("[*] Making list for dynamic bruteforce ...")
    subprocess.run(f"cat {domain}.passivesubs.txt {domain}.staticbrute.txt | sort -u | dnsgen -w words-merged.txt - > dynamic-list.txt" , shell=True, check=True)
    Num_of_Words = subprocess.run("cat dynamic-list.txt | wc -l" , shell=True , check=True , capture_output=True)
    print(f"[*] Number of words in your wordlist for dynamic bruteforce is: {int(Num_of_Words.stdout)}")
    print("[*] Split file into 1M lines files ...")

    t = subprocess.run(f"split -l 1000000 dynamic-list.txt dsplitted.{domain}.; ls dsplitted*", shell=True , check=True , capture_output=True)
    Files = t.stdout.decode("utf-8").split("\n")
    print("[*] Starting Dynamic DNS Bruteforce ...")
    i = 1
    for file in Files:
        if file != "":

            print(f"[*] Dynamic Bruteforce on {file} ...")
            subprocess.run(f"cat {file} | shuffledns -d {domain} -r resolvers.txt -m /usr/local/bin/massdns -o {domain}.dynamicbrute{i}.txt -silent" , shell=True , check=True)
            i = i + 1

    print("Dynamic Bruteforce is done.")

    subprocess.run(f"cat {domain}.dynamicbrute* > {domain}.dynamicbrute.txt" , shell=True , check=True)
    subprocess.run("rm splitted* dsplitted*" , shell=True , check=True)
    subprocess.run(f"cat {domain}.passivesubs.txt {domain}.dynamicbrute.txt {domain}.staticbrute.txt| sort -u > {domain}.allsubs.txt")

def main():
    parser = argparse.ArgumentParser(description="Finding subdomains as much as possible.")
    parser.add_argument('-d', '--domain', help='Target Domain')

    args = parser.parse_args()

    if args.domain:
        domain = args.domain
        Passive_Subdomains(domain)
        DNS_BruteForce(domain)
        
    else:
        print("Please provide a domain using the '-d' or '--domain' switch.")

if __name__ == "__main__":
    banner()
    main()