import subprocess
import sys
import os
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
collect_subdomains()
# function for extract all subdomain with all file and give all_Subdomains.txt
def all_Subdomains():
    result_all = subprocess.run(['cat ./subdomains/*.txt | sort | uniq > all_Subdomains.txt'])

