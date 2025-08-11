#!/bin/bash
#
if [ -z $1  ]; then
    echo -e "\e[31mUsage: $0 <target>\e[0m"
    echo -e "\e[31m./recon.sh --help \e[0m"
    exit 1
fi
cat ./wordlist/recon
# target
TARGET=$1
if [ -z $TARGET ]; then
	figlet $TARGET
fi
# Function to collect subdomains
collect_subdomains() {
mkdir -p ./$TARGET/subdomains
    echo -e "\e[34m[*] Running subfinder...\e[0m"
    subfinder -d "$TARGET" -silent | awk '{print "https://"$0}'  >  ./$TARGET/subdomains/subfinder_subs.txt
     echo -e "\e[34m[*] Running findomain...\e[0m"
     findomain -q -t "$TARGET" | awk '{print "https://"$0}' > ./$TARGET/subdomains/findomain_subs.txt
    echo -e "\e[34m[*] Running assetfinder...\e[0m"
    assetfinder -subs-only "$TARGET" | awk '{print "https://"$0}' > ./$TARGET/subdomains/assetfinder_subs.txt
	echo -e "\e[32m[*] Extracting all subdomains...\e[0m"
    cat ./$TARGET/subdomains/*.txt | sort | uniq >> ./$TARGET/subdomains/all_subdomains.txt
}
collect_subdomains_subs() {
	mkdir -p ./sub
    echo -e "\e[34m[*] Find subdomains  subdomains \e[0m"
	cat ./$TARGET/subdomains/all_subdomains.txt | while ifs= read -r sub  ; do
		echo $sub
		subfinder -d "$sub" -silent >> ./$TARGET/subdomains/subs_subs_s.txt
		assetfinder -subs-only "$sub" -silent >> ./$TARGET/subdomains/subs_subs_a.txt
		cat ./$TARGET/subdomains/*  | sort | uniq > ./$TARGET/subdomains/all_subdomains.txt
	done
}
# extract live subdomains
live_subs() {
	mkdir -p ./$TARGET/live_subs
    echo -e "\e[32m[*] Extracting live subdomains...\e[0m"
    echo -e "\e[34m[*] Running httpx...\e[0m"
    httpx -silent -l  ./$TARGET/subdomains/all_subdomains.txt -o ./$TARGET/live_subs/live_subdomains.txt 
}
# extract all URLs
all_links_domain() {
	mkdir -p ./$TARGET/urls
    echo -e "\e[34m[*] Extracting all URLs...\e[0m"
    echo -e "\e[34m[*] Running hakrawler...\e[0m"
    if [ -s ./$TARGET/live_subs/live_subdomains.txt ]; then
        echo -e "\e[32m[*] Running hakrawler on live_subdomains...\e[0m"
        cat ./$TARGET/live_subs/live_subdomains.txt | hakrawler > ./$TARGET/urls/all_urls.txt
        cat ./$TARGET/live_subs/live_subdomains.txt | waybackurls >> ./$TARGET/urls/all_urls.txt
		cat ./$TARGET/urls/*  | sort | uniq > ./$TARGET/urls/all_urls.txt
    elif [ -s ./$TARGET/subdomains/all_subdomains.txt ]; then
		live_subs
        echo -e "\e[32m[*] Running hakrawler on live_subdomains...\e[0m"
        cat ./$TARGET/live_subs/live_subdomains.txt | hakrawler > ./$TARGET/urls/all_urls.txt
        cat ./$TARGET/live_subs/live_subdomains.txt | waybackurls >> ./$TARGET/urls/all_urls.txt
		cat ./$TARGET/urls/*  | sort | uniq > ./$TARGET/urls/all_urls.txt
    else
        echo -e "\e[32m[*] Running other function for run hakrawler on the live subdomains...\e[0m"
		collect_subdomains
		live_subs
        cat ./$TARGET/live_subs/live_subdomains.txt | hakrawler > ./$TARGET/urls/all_urls.txt
        cat ./$TARGET/live_subs/live_subdomains.txt | waybackurls >> ./$TARGET/urls/all_urls.txt
		cat ./$TARGET/urls/*  | sort | uniq > ./$TARGET/urls/all_urls.txt
    fi
}
sqli () {
	mkdir -p ./$TARGET/url_possible_vulnarblities
	if [ -s ./$TARGET/urls/all_urls.txt ]; then
		echo "1"
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf sqli > ./$TARGET/url_possible_vulnarblities/sqli.txt
	elif [ -s ./$TARGET/live_subs/live_subdomains.txt ]; then
		echo "2"
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf sqli > ./$TARGET/url_possible_vulnarblities/sqli.txt
	elif [ -s ./$TARGET/subdomains/all_subdomains.txt ]; then
		echo "3"
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf sqli > ./$TARGET/url_possible_vulnarblities/sqli.txt
	else
		echo "4"
		collect_subdomains
		# collect_subdomains_subs
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf sqli > ./$TARGET/url_possible_vulnarblities/sqli.txt
	fi
}
rce () {
	mkdir -p ./$TARGET/url_possible_vulnarblities
	if [ -s ./$TARGET/urls/all_urls.txt ]; then
		echo "1"
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf rce > ./$TARGET/url_possible_vulnarblities/rce.txt
	elif [ -s ./$TARGET/live_subs/live_subdomains.txt ]; then
		echo "2"
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf rce > ./$TARGET/url_possible_vulnarblities/rce.txt
	elif [ -s ./$TARGET/subdomains/all_subdomains.txt ]; then
		echo "3"
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf rce > ./$TARGET/url_possible_vulnarblities/rce.txt
	else
		echo "4"
		collect_subdomains
		# collect_subdomains_subs
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf rce > ./$TARGET/url_possible_vulnarblities/rce.txt
	fi
}
ssti () {
	mkdir -p ./$TARGET/url_possible_vulnarblities
	if [ -s ./$TARGET/urls/all_urls.txt ]; then
		echo "1"
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssti > ./$TARGET/url_possible_vulnarblities/ssti.txt
	elif [ -s ./$TARGET/live_subs/live_subdomains.txt ]; then
		echo "2"
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssti > ./$TARGET/url_possible_vulnarblities/ssti.txt
	elif [ -s ./$TARGET/subdomains/all_subdomains.txt ]; then
		echo "3"
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssti > ./$TARGET/url_possible_vulnarblities/ssti.txt
	else
		echo "4"
		collect_subdomains
		# collect_subdomains_subs
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssti > ./$TARGET/url_possible_vulnarblities/ssti.txt
	fi
}
ssrf () {
	mkdir -p ./$TARGET/url_possible_vulnarblities
	if [ -s ./$TARGET/urls/all_urls.txt ]; then
		echo "1"
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssrf > ./$TARGET/url_possible_vulnarblities/ssrf.txt
	elif [ -s ./$TARGET/live_subs/live_subdomains.txt ]; then
		echo "2"
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssrf > ./$TARGET/url_possible_vulnarblities/ssrf.txt
	elif [ -s ./$TARGET/subdomains/all_subdomains.txt ]; then
		echo "3"
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssrf > ./$TARGET/url_possible_vulnarblities/ssrf.txt
	else
		echo "4"
		collect_subdomains
		# collect_subdomains_subs
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf ssrf > ./$TARGET/url_possible_vulnarblities/ssrf.txt
	fi
}
xss () {
	mkdir -p ./$TARGET/url_possible_vulnarblities
	if [ -s ./$TARGET/urls/all_urls.txt ]; then
		echo "1"
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf xss > ./$TARGET/url_possible_vulnarblities/xss.txt
	elif [ -s ./$TARGET/live_subs/live_subdomains.txt ]; then
		echo "2"
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf xss > ./$TARGET/url_possible_vulnarblities/xss.txt
	elif [ -s ./$TARGET/subdomains/all_subdomains.txt ]; then
		echo "3"
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf xss > ./$TARGET/url_possible_vulnarblities/xss.txt
	else
		echo "4"
		collect_subdomains
		# collect_subdomains_subs
		live_subs
		all_links
		cat ./$TARGET/urls/all_urls.txt | ~/go/bin/gf xss > ./$TARGET/url_possible_vulnarblities/xss.txt
	fi
}




main () {
	collect_subdomains
	collect_subdomains_subs
	live_subs
    # all_links_domain
	# sqli
	# rce
	# ssti
	# ssrf
	# xss
}
main
