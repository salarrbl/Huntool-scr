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
    httpx -silent -l ./$TARGET/subdomains/all_subdomains.txt -o ./$TARGET/live_subs/live_subdomains.txt
}

# extract all URLs
all_links() {
	mkdir -p ./$TARGET/urls
    echo -e "\e[34m[*] Extracting all URLs...\e[0m"
    echo -e "\e[34m[*] Running hakrawler...\e[0m"

    if [ -s ./$TARGET/live_subs/live_subdomains.txt ]; then
        echo -e "\e[32m[*] Running hakrawler on live_subdomains...\e[0m"
        cat ./$TARGET/live_subs/live_subdomains.txt | hakrawler > ./$TARGET/urls/all_urls.txt
    elif [ -s ./$TARGET/subdomains/all_subdomains.txt ]; then
        echo -e "\e[32m[*] Running hakrawler on all_subdomains...\e[0m"
        cat ./$TARGET/subdomains/all_subdomains.txt | hakrawler > ./$TARGET/urls/all_urls.txt
    else
        echo -e "\e[32m[*] Running hakrawler on original domain...\e[0m"
		target=$TARGET
		echo $target
        echo "https://$target" | hakrawler >> ./$TARGET/urls/all_urls.txt
    fi
}
hidden_directories_files_main() {
    echo -e "\e[34m[*] Running ffuf on original input \e[0m"
	mkdir -p ./$TARGET/FUZZ
    ffuf -u "https://$TARGET/FUZZ" -w wordlist/raft-small.txt -c  -mc 200,204,301,302,307,403,405,500  | awk -v tgt="https://$TARGET/" '{print tgt $1}' | tee ./$TARGET/FUZZ/ffuf_res.txt
}
hidden_directories_files_live_subs() {
    echo -e "\e[34m[*] Running ffuf on live_subdomains\e[0m"
	mkdir -p ./$TARGET/FUZZ
	cat ./codeyad.com/live_subs/live_subdomains.txt | while ifs= read -r subs; do 
		ffuf -u  "https://$TARGET/FUZZ" -w wordlist/raft-small.txt -c   -mc 200,204,301,302,307,403,405,500  | awk -v tgpt="https://$TARGET/" '{print tgt $1}' | tee ./$TARGET/FUZZ/ffuf_res_subs.txt
	done
}
all_link_parametr() {
		cat ./$TARGET/urls/all_urls.txt | while ifs= read -r parametrs; do
			x8 -u "$parametrs" -w ./wordlist/parms.txt >> ./$TARGET/parametrs/parametrs.txt
		done
}
main () {
	# collect_subdomains
	# live_subs
    # all_links
	# parametrs
	hidden_directories_files_main
	# hidden_directories_files_live_subs
	# all_link_parametr
}
main
