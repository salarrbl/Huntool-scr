#!/usr/bin/env bash

if [ -z $1  ]; then
    echo -e "\e[31mUsage: $0 <target>\e[0m"
    echo -e "\e[31m./recon.sh --help \e[0m"
    exit 1
fi
# cat ./wordlist/recon
echo """
__________                                       _________               
\______   \ ____   ____  ____   ____            /   _____/______   ____  
 |       _// __ \_/ ___\/  _ \ /    \   ______  \_____  \\_  __ \_/ ___\ 
 |    |   \  ___/\  \__(  <_> )   |  \ /_____/  /        \|  | \/\  \___ 
 |____|_  /\___  >\___  >____/|___|  /         /_______  /|__|    \___  >
        \/     \/     \/           \/                  \/             \/ 

"""
# Function to collect subdomains
f_u() {
	# echo $2
	mkdir -p ./$TARGET/subdomains
    echo -e "\e[34m[*] * Running subfinder...\e[0m"
    subfinder -d "$TARGET" -silent | awk '{print "https://"$0}'  >  ./$TARGET/subdomains/subfinder_subs.txt
    echo -e "\e[34m[*] * Running findomain...\e[0m"
    findomain -q -t "$TARGET" | awk '{print "https://"$0}' > ./$TARGET/subdomains/findomain_subs.txt
    echo -e "\e[34m[*] * Running assetfinder...\e[0m"
    assetfinder -subs-only "$TARGET" | awk '{print "https://"$0}' > ./$TARGET/subdomains/assetfinder_subs.txt
	echo -e "\e[32m[*] * Extracting all uniq subdomains...\e[0m"
    cat ./$TARGET/subdomains/*.txt | sort | uniq >> ./$TARGET/subdomains/all_subdomains.txt
	echo -e "\e[32m[*] Extracting live subdomains...\e[0m"
	cat ./$TARGET/subdomains/all_subdomains.txt | dnsx -retry 10 -r ~/.resolvers -duc -silent | httpx -title -sc -duc -cdn -retries 3 -cl >  ./$TARGET/subdomains/live_subdomains.txt

}

f_uss() {
	echo -e "\e[34m[*] * Find subdomains  subdomains \e[0m"
	cat ./$TARGET/subdomains/all_subdomains.txt | while ifs= read -r sub  ; do
		echo $sub
		subfinder -d "$sub" -silent | awk '{print "https://"$0}'  >> ./$TARGET/subdomains/subs_subs_s.txt
		assetfinder -subs-only "$sub" -silent | awk '{print "https://"$0}'  >> ./$TARGET/subdomains/subs_subs_a.txt
		findomain -q -t "$TARGET" | awk '{print "https://"$0}' > ./$TARGET/subdomains/findomain_subs.txt
		cat ./$TARGET/subdomains/*  | sort | uniq > ./$TARGET/subdomains/all_subdomains.txt
	done

}

# for read multi domains on a file
f_fm() {
	for t in $(cat "$TARGET"); do
		echo "$t"
		mkdir -p "./$t/subdomains"
		echo "target now is $t"
		echo -e "\e[34m[*] Running subfinder...\e[0m"
		subfinder  -all -d "$t" -silent | awk '{print "https://"$0}' > "./$t/subdomains/subfinder_subs.txt"
		echo -e "\e[34m[*] Running findomain...\e[0m"
		findomain -q -t "$t" | awk '{print "https://"$0}' > "./$t/subdomains/findomain_subs.txt"
		echo -e "\e[34m[*] Running assetfinder...\e[0m"
		assetfinder -subs-only "$t" | awk '{print "https://"$0}' > "./$t/subdomains/assetfinder_subs.txt"
		echo -e "\e[32m[*] Extracting all unique subdomains...\e[0m"
		cat "./$t/subdomains/"*.txt | sort -u > "./$t/subdomains/all_subdomains.txt"
		echo -e "\e[34m[*] * Find subdomains  subdomains \e[0m"
		echo -e "\e[32m[*] Extracting live subdomains...\e[0m"
 		cat ./$t/subdomains/all_subdomains.txt | dnsx -retry 10 -r ~/.resolvers -duc -silent | httpx -title -sc -duc -cdn -retries 3 -cl >  ./$t/subdomains/live_subdomains.txt
		# httpx -silent -l "./$t/subdomains/all_subdomains.txt" -o "./$t/subdomains/live_subdomains.txt"
	done
}

# for multi domains and get subs subs
f_fss() {
	for t in $(cat "$TARGET"); do
		echo "$t"
		mkdir -p "./$t/subdomains"
		echo "target now is $t"
		echo -e "\e[34m[*] Running subfinder...\e[0m"
		subfinder -d "$t" -silent | awk '{print "https://"$0}' > "./$t/subdomains/subfinder_subs.txt"
		echo -e "\e[34m[*] Running findomain...\e[0m"
		findomain -q -t "$t" | awk '{print "https://"$0}' > "./$t/subdomains/findomain_subs.txt"
		echo -e "\e[34m[*] Running assetfinder...\e[0m"
		assetfinder -subs-only "$t" | awk '{print "https://"$0}' > "./$t/subdomains/assetfinder_subs.txt"
		echo -e "\e[32m[*] Extracting all unique subdomains...\e[0m"
		cat ./$t/subdomains/all_subdomains.txt | while ifs= read -r sub  ; do
			echo "get subdomains for this subdomains $sub"
			subfinder -d "$sub" -silent | awk '{print "https://"$0}'  >> ./$t/subdomains/subs_subs_s.txt
			assetfinder -subs-only "$sub" -silent | awk '{print "https://"$0}'  >> ./$t/subdomains/subs_subs_a.txt
			findomain -q -t "$t" | awk '{print "https://"$0}' > ./$t/subdomains/findomain_subs.txt
			cat ./$t/subdomains/*  | sort | uniq > ./$t/subdomains/all_subdomains.txt
		done
		cat "./$t/subdomains/"*.txt | sort -u > "./$t/subdomains/all_subdomains.txt"
		echo -e "\e[32m[*] Extracting live subdomains...\e[0m"
		httpx -silent -l "./$t/subdomains/all_subdomains.txt" -o "./$t/subdomains/live_subdomains.txt"
	done
}




# for extracting all js file and donloads and search for api keys
f_jsu() {
	mkdir -p ./$TARGET/JS
	echo " * run gau and waybackurl"
	gau "$DOMAIN" | grep '\.js' | tee ./$TARGET/gau-js.txt
	cat "$DOMAIN" | waybackurls | grep '\.js' | tee ./$TARGET/wayback-js.txt
	echo " * run katana"
	katana -u "https://$DOMAIN" -silent | grep '\.js' | tee ./$TARGET/katana-js.txt
	cat gau-js.txt katana-js.txt wayback-js.txt >> alljs.txt
	sed -E 's/(\.js).*$/\1/' alljs.txt | sort -u > alljsclean.txt
	rm -rf gau-js.txt katana-js.txt alljs.txt
	echo " * Downloading JS files..."
	while read -r url; do
	  filename=$(basename "$url")
	  filepath="JS/$filename"
	  # Avoid overwriting if same filename comes from multiple sources
	  if [ -e "$filepath" ]; then
		hash=$(echo -n "$url" | md5sum | cut -d ' ' -f1)
		filepath="jss/${hash}_$filename"
	  fi
	  # Download JS file with URL as comment
	  echo "// $url" > "$filepath"
	  curl -s "$url" >> "$filepath"
	  echo "* Downloaded: $url -> $filepath"
	done < alljsclean.txt


}


help="""
-us            get subdomains for a url(domain)
-uss           get subdomains and subdomains subdomains for a url(domain)
-fs            get subdomains for multi domain on a file
-fss           get subdomains for multi domain on a file and subdomains for each subdomains
-ujs           Download all js file and search api keys
"""
case $1 in
	"-us")
		TARGET=$2
		f_u
		;;
	"-uss")
		TARGET=$2
		f_u
		f_uss
		;;
	"-fs")
		TARGET=$2
		f_fm
		echo "1"
		;;
	"-fss")
		TARGET=$2
		f_fss
		;;
	"-ujs")
		TARGET=$2
		f_jsu
		;;
	"--help")
		echo """
-us            get subdomains for a url(domain)
-uss           get subdomains and subdomains subdomains for a url(domain)
-fs            get subdomains for multi domain on a file
-fss           get subdomains for multi domain on a file and subdomains for each subdomains
-ujs           Download all js file and search api keys
"""
		;;
	*)
		exit
		;;
esac
