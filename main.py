import subprocess
import colorama
import sys
import os
import glob
if len(sys.argv) != 2:
    print(colorama.Fore.RED, "Usage: python script.py <target>")
    sys.exit(1)

# Give Target
target = sys.argv[1]
# function for subfinder
def collect_subdomains():
    # Run Subfinder on the target 
    direc_subs = './subdomains'
    if os.path.exists(direc_subs):
        print('')
    else:
        subprocess.run(['mkdir' , 'subdomains'])
    subprocess.run(['bash', '-c', f'cd {'./subdomains'} && ls'])
    print(colorama.Fore.BLUE, "{*}subfinder running :")
    result = subprocess.run(['subfinder', '-d', target, '-silent'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Storing the result
    output = result.stdout
    error = result.stderr
    if (output):
        with open('./subdomains/Subfinder_subs.txt', 'a') as file:
            file.write(output)
    if (error):
        print("Error:", error)
    print(colorama.Fore.BLUE, "{*} findomain running :")
    result2 = subprocess.run(['findomain', '-q', '-t', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # print(result2)
    output2 = result2.stdout
    error2 = result2.stderr
    if (output2):
        with open('./subdomains/findomain_subs.txt', 'a') as file:
            file.write(output)
    if (error2):
        print("Error:", error)

    print(colorama.Fore.BLUE, "(*) assetfinder running :")
    result3 = subprocess.run(['assetfinder', '-subs-only', target, ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Storing the result
    output3 = result.stdout
    error3 = result.stderr
    if (output3):
        with open('./subdomains/assetfinder_subs.txt', 'a') as file:
            file.write(output)
    if (error3):
        print("Error:", error3)
    
# function for extract all subdomain with all file and give all_Subdomains.txt
def all_Subdomains():
    # result_all = subprocess.run(['cat ./subdomains/*.txt | sort | uniq > all_Subdomains.txt'])
    print(colorama.Fore.GREEN ,"{*} extracting all subdomains")
    files = glob.glob('./subdomains/*.txt')
    #my command
    command = 'cat ' + ' '.join(files) + ' | sort | uniq > ./subdomains/all_Subdomains.txt'
    result = subprocess.run(['bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def live_subs():
    print(colorama.Fore.GREEN, "extracting Live Subdomains") 
    print(colorama.Fore.BLUE, "{*} running httpx")
    direc_subs = './live_subs'
    if os.path.exists(direc_subs):
        print('')
    else:
        subprocess.run(['mkdir' , 'live_subs'])

    #httpx -silent -l all_Subdomains.txt -o live_subdomains.tx
    subprocess.run(['httpx', '-silent', '-l', './subdomains/all_Subdomains.txt', '-o', './live_subs/live_subdomains.txt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)



def all_links():
    print(colorama.Fore.BLUE, "{*}extracting all Urls")
    print(colorama.Fore.BLUE, "{*} running hakrawler")
    durl = './urls'
    if os.path.exists(durl):
        print('')
    else:
        subprocess.run(['mkdir' , 'urls'])

    #give all link
    path_domains = './live_subs/live_subdomains.txt'
    path_domains2 = './subdomains/all_Subdomains.txt'
    if os.path.exists(path_domains) and os.path.getsize(path_domains) > 0:
        print("{**} running hakrawler on live_subdomains")
        url_command = 'cat ./live_subs/live_subdomains.txt | hakrawler'
        res_urls = subprocess.run(['bash', '-c', url_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_url = res_urls.stdout
        error_url = res_urls.stderr
        if (output_url):
            with open('./urls/all_urls.txt', 'a') as file:
                file.write(output_url)
        if (error_url):
            print("Error:", error_url)
    elif os.path.exists(path_domains2) and os.path.getsize(path_domains2) > 0:
        print("{**} running hakrawler on all_Subdomains")
        url_command2 = 'cat ./subdomains/all_Subdomains.txt | hakrawler'
        res_urls2 = subprocess.run(['bash', '-c', url_command2], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_url2 = res_urls2.stdout
        error_url2 = res_urls2.stderr
        if (output_url2):
            with open('./urls/all_urls.txt', 'a') as file:
                file.write(output_url2)
        if (error_url2):
            print("Error:", error_url2)
    else:
        print("{**} running hakrawler on orginal Domain")
        with open('target', 'w') as file:
            file.write(target)
        url_command3 = 'cat ./target | hakrawler'
        res_urls3 = subprocess.run(['bash', '-c', url_command3], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_url3 = res_urls3.stdout
        error_url3 = res_urls3.stderr
        if (output_url3):
            with open('./urls/all_urls.txt', 'a') as file:
                file.write(output_url3)
        if (error_url3):
            print("Error:", error_url3)


def Hidden_directorys_files():
#testing b fuff
#ffuf -u https://newamooz.com/FUZZ -w wordlist/words.txt -mc 200,403
    print(colorama.Fore.BLUE, "{*} ffuf running")
    dfuff = './Hidden_directorys_files'
    if os.path.exists(dfuff):
        print('')
    else: 
        subprocess.run(['mkdir', 'Hidden_directorys_files'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    command_fuff = 'ffuf -u https://' + target +'/FUZZ' + ' -w wordlist/words.txt -mc 200,403'
    res_ffuf = subprocess.run(['bash', '-c', command_fuff], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_ffuf = res_ffuf.stdout
    if (output_ffuf):
         with open('./Hidden_directorys_files/ffuf_res.txt', 'a') as file:
             file.write(output_ffuf)
def port_scan():
    print(colorama.Fore.MAGENTA, "{*} run a script for port scan and grap baner")
    subprocess.run(['bash', '-c', './port_scan/script.sh'])

def url_possible_vuln():
    print(colorama.Fore.BLUE, "{*} gf running")
    dvunls = './url_possible_vulnarblities'
    if os.path.exists(dvunls):
        print('')
    else: 
        subprocess.run(['mkdir', 'url_possible_vulnarblities'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    #for xss 
    command_gf_xss = 'cat ./urls/all_urls.txt | ~/go/bin/gf xss'
    res_gf_xss = subprocess.run(['bash', '-c', command_gf_xss], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_xss = res_gf_xss.stdout
    if (output_xss):
         with open('./url_possible_vulnarblities/xss.txt', 'a') as file:
             file.write(output_xss)
    #for sql injections
    command_gf_sqli = 'cat ./urls/all_urls.txt | ~/go/bin/gf sqli'
    res_gf_sqli = subprocess.run(['bash', '-c', command_gf_sqli], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_sqli = res_gf_sqli.stdout
    if (output_sqli):
         with open('./url_possible_vulnarblities/sqli.txt', 'a') as file:
             file.write(output_sqli)
    #for Server Site Template Injection
    command_gf_ssti = 'cat ./urls/all_urls.txt | ~/go/bin/gf ssti'
    res_gf_ssti = subprocess.run(['bash', '-c', command_gf_ssti], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_ssti = res_gf_ssti.stdout
    if (output_ssti):
         with open('./url_possible_vulnarblities/SSTI.txt', 'a') as file:
             file.write(output_ssti)
    
    #for Server Site Forgive Request
    command_gf_ssrf = 'cat ./urls/all_urls.txt | ~/go/bin/gf ssrf'
    res_gf_ssrf = subprocess.run(['bash', '-c', command_gf_ssrf], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_ssrf = res_gf_ssrf.stdout
    if (output_ssrf):
         with open('./url_possible_vulnarblities/SSRF.txt', 'a') as file:
             file.write(output_ssrf)
     #for Remote Code Injection
    command_gf_rce = 'cat ./urls/all_urls.txt | ~/go/bin/gf rce'
    res_gf_rce = subprocess.run(['bash', '-c', command_gf_rce], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_rce = res_gf_rce.stdout
    if (output_rce):
         with open('./url_possible_vulnarblities/RCE.txt', 'a') as file:
             file.write(output_rce)
    #for idor
    command_gf_idor = 'cat ./urls/all_urls.txt | ~/go/bin/gf idor'
    res_gf_idor = subprocess.run(['bash', '-c', command_gf_idor], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_idor = res_gf_idor.stdout
    if (output_idor):
         with open('./url_possible_vulnarblities/IDOR.txt', 'a') as file:
             file.write(output_idor)
    files1 = glob.glob('./url_possible_vulnarblities/*.txt')
    #my command
    command1 = 'cat ' + ' '.join(files1) + ' | sort | uniq > ./url_possible_vulnarblities/all_possible_vulns_urls.txt'
    subprocess.run(['bash', '-c', command1], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
def js_files():
    print(colorama.Fore.GREEN, "{*} Extracting all js files")
    d = './js_files'
    if os.path.exists(d):
        print('')
    else: 
        subprocess.run(['mkdir', 'js_files'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
   
    command_js = 'cat ./urls/all_urls.txt | grep js '
    res_js = subprocess.run(['bash', '-c', command_js], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output_js = res_js.stdout
    if (output_js):
         with open('./js_files/all_js_file.txt', 'a') as file:
             file.write(output_js)
def nuclie():
    subprocess.run(['bash', '-c', './nuclei/script.sh'])
def main():
    collect_subdomains()
    all_Subdomains()
    live_subs()
    all_links()
    Hidden_directorys_files()
    port_scan()
    url_possible_vuln()
    js_files()
    nuclie()

main()
