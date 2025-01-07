import subprocess
import sys
import os
import glob
if len(sys.argv) != 2:
    print("Usage: python script.py <target>")
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
    print("subfinder running :")
    result = subprocess.run(['subfinder', '-d', target, '-silent'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Storing the result
    output = result.stdout
    error = result.stderr
    if (output):
        with open('./subdomains/Subfinder_subs.txt', 'a') as file:
            file.write(output)
    if (error):
        print("Error:", error)
    print("findomain running :")
    result2 = subprocess.run(['findomain', '-q', '-t', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # print(result2)
    output2 = result2.stdout
    error2 = result2.stderr
    if (output2):
        with open('./subdomains/findomain_subs.txt', 'a') as file:
            file.write(output)
    if (error2):
        print("Error:", error)

    print("(*) assetfinder running :")
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
    files = glob.glob('./subdomains/*.txt')
    #my command
    command = 'cat ' + ' '.join(files) + ' | sort | uniq > ./subdomains/all_Subdomains.txt'
    result = subprocess.run(['bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)






def live_subs():
    print("extracting Live Subdomains")
    subprocess.run(['mkdir', 'live_subs'])
    #httpx -silent -l all_Subdomains.txt -o live_subdomains.tx
    subprocess.run(['httpx', '-silent', '-l', './subdomains/all_Subdomains.txt', '-o', './live_subs/live_subdomains.txt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
live_subs()


