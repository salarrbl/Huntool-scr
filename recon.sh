#!/bin/bash

# 
if [ -z $1  ]; then
    echo -e "\e[31mUsage: $0 <target>\e[0m"
    echo -e "\e[31m./recon.sh --help or -h\e[0m"
    exit 1
fi

# target 
TARGET=$1
if [ -z $TARGET ]; then
	figlet $TARGET
fi
# Function to collect subdomains
collect_subdomains() {
    echo -e "\e[34m[*] Running subfinder...\e[0m"
    subfinder -d "$TARGET" -silent > ./result/subdomains/subfinder_subs.txt

    echo -e "\e[34m[*] Running findomain...\e[0m"
    findomain -q -t "$TARGET" > ./result/subdomains/findomain_subs.txt

    echo -e "\e[34m[*] Running assetfinder...\e[0m"
    assetfinder -subs-only "$TARGET" > ./result/subdomains/assetfinder_subs.txt

	echo -e "\e[32m[*] Extracting all subdomains...\e[0m"
    cat ./result/subdomains/*.txt | sort | uniq > ./result/subdomains/all_subdomains.txt

}

    
# extract live subdomains
live_subs() {
    echo -e "\e[32m[*] Extracting live subdomains...\e[0m"
    echo -e "\e[34m[*] Running httpx...\e[0m"
    httpx -silent -l ./result/subdomains/all_subdomains.txt -o ./result/live_subs/live_subdomains.txt
}

# extract all URLs
all_links() {
    echo -e "\e[34m[*] Extracting all URLs...\e[0m"
    echo -e "\e[34m[*] Running hakrawler...\e[0m"

    if [ -s ./result/live_subs/live_subdomains.txt ]; then
        echo -e "\e[32m[*] Running hakrawler on live_subdomains...\e[0m"
        cat ./result/live_subs/live_subdomains.txt | hakrawler > ./result/urls/all_urls.txt
    elif [ -s ./result/subdomains/all_subdomains.txt ]; then
        echo -e "\e[32m[*] Running hakrawler on all_subdomains...\e[0m"
        cat ./result/subdomains/all_subdomains.txt | hakrawler > ./result/urls/all_urls.txt
    else
        echo -e "\e[32m[*] Running hakrawler on original domain...\e[0m"
        echo "https://$TARGET" | hakrawler > ./result/urls/all_urls.txt
    fi
}

parametrs() {
	cat ./result/urls/all_urls.txt | while ifs= read -r parametrs; do
		x8 -u "$parametrs" -w ./wordlist/parms.txt > ./result/parametrs/p.txt
	done
}
# find hidden directories/files
hidden_directories_files() {
    echo -e "\e[34m[*] Running ffuf...\e[0m"
    ffuf -u "https://$TARGET/FUZZ" -w wordlist/words.txt  -o ./result/hidden_directorys_files/ffuf_res.txt
}

# port scanning with nmap 
port_scan() {
    echo -e "\e[35m[*] Running nmap...\e[0m"
    nmap -sC -sV -p- "$TARGET" -oN ./result/nmap-results.txt
	
}

all_subs_port_scan() {
	echo -e "\e[34m[*] Running Nuclei...\e[0m"
	cat ./result/live_subs/live_subdomains.txt | while ifs= read -r purl; do
		echo "runing nmap  on the $purl"
		nmap -sC -sV -p- "$purl" -oN ./result/nmap-subs-result.txt
	done 
}
# find possible vulnerabilities in URLs with gf
url_possible_vuln() {
    echo -e "\e[34m[*] Running gf...\e[0m"
    # XSS
    cat ./result/urls/all_urls.txt | ~/go/bin/gf xss > ./result/url_possible_vulnarblities/xss.txt
    cat ./result/parametrs/p.txt | ~/go/bin/gf xss >> ./result/url_possible_vulnarblities/xss.txt
    # SQL Injection
    cat ./result/urls/all_urls.txt | ~/go/bin/gf sqli > ./result/url_possible_vulnarblities/sqli.txt
    cat ./result/parametrs/p.txt | ~/go/bin/gf sqli >> ./result/url_possible_vulnarblities/sqli.txt
    # SSTI
    cat ./result/urls/all_urls.txt | ~/go/bin/gf ssti > ./result/url_possible_vulnarblities/ssti.txt
    cat ./result/parametrs/p.txt | ~/go/bin/gf ssti >> ./result/url_possible_vulnarblities/ssti.txt
    # SSRF
    cat ./result/urls/all_urls.txt | ~/go/bin/gf ssrf > ./result/url_possible_vulnarblities/ssrf.txt
    cat ./result/parametrs/p.txt | ~/go/bin/gf ssrf >> ./result/url_possible_vulnarblities/ssrf.txt
    # RCE
    cat ./result/urls/all_urls.txt | ~/go/bin/gf rce > ./result/url_possible_vulnarblities/rce.txt
    cat ./result/parametrs/p.txt | ~/go/bin/gf rce >> ./result/url_possible_vulnarblities/rce.txt
    # IDOR
    cat ./result/urls/all_urls.txt | ~/go/bin/gf idor > ./result/url_possible_vulnarblities/idor.txt
    cat ./result/parametrs/p.txt | ~/go/bin/gf idor >> ./result/url_possible_vulnarblities/idor.txt
	# redirect 
    cat ./result/urls/all_urls.txt | ~/go/bin/gf redirect > ./result/url_possible_vulnarblities/redirect.txt
    cat ./result/parametrs/p.txt | ~/go/bin/gf redirect >> ./result/url_possible_vulnarblities/redirect.txt
    # Combine all results
    cat ./result/url_possible_vulnarblities/*.txt | sort | uniq > ./result/url_possible_vulnarblities/all_possible_vulns_urls.txt
}

# Function to extract JS files
js_files() {
    echo -e "\e[32m[*] Extracting all JS files...\e[0m"
    cat ./result/urls/all_urls.txt | grep "\.js$" > ./result/js_files/all_js_file.txt
}

# Nuclei
nuclie() {
    echo -e "\e[34m[*] Running Nuclei...\e[0m"
	cat ./result/live_subs/live_subdomains.txt | while ifs= read -r url; do
		echo "runing nuclie on the $url"
		nuclei -silent -si 30 -stats -u "$url"  -es info,low -etags network -o ./result/nuclie_res/nuclei_output.txt -rl 100;
	done 
}



commix() {
	while read -r target_commix; do
		commix --url "$target_commix" --batch
	done < ./result/url_possible_vulnarblities/rce.txt

}

sqlmap() {
	while read -r target_sqli; do
    	sqlmap --url "$target_sqli" --batch --dbs
	done < ./result/url_possible_vulnarblities/sqli.txt

}



mkdir -p ./result/{subdomains,live_subs,urls,hidden_directorys_files,url_possible_vulnarblities,js_files}
case "$2" in
	-subs)
		collect_subdomains
		;;
	-live-subs)
		live_subs
		;;
	-links)
		all_links
		;;
	-hiddens)
		hidden_directories_files
		;;
	-ports)
		port_scan
		;;
	-vuln-url)
		url_possible_vuln
		;;
	-js)
		js_files
		;;
	-nuclei)
		nuclie
		;;

	-commix)
		commix
		;;
	-sqlmap)
		sqlmap
		;;

esac
case "$1" in
	--help | -h)
		echo "
		-subs          find subdomains
		-live_subs     extract only live subdomains
		-links         Extract all link(live subdomains or just target)
		-hiddens       find hidden file or directory by ffuf 
		-ports         port scan with nmap 
		-vuln-url      extract urls possible be vulnerabilities by gf 
		-js            extract all js file 
		-nuclie        Vulnerability Scanners with nuclie
		-commix        run commix to the ./result/url_possible_vulnarblities/rce.txt
		-sqlmap        run sqlmap  to the ./result/url_possible_vulnarblities/sqli.txt
		"
		;;
esac
