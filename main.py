import subprocess
import sys

if len(sys.argv) != 2:
    print("Usage: python script.py <target>")
    sys.exit(1)

# Give Target
target = sys.argv[1]
# function for subfinder
def collect_subdomains():
    print("subfinder running :")
    # Run Subfinder on the target 
    result = subprocess.run(['subfinder', '-d', target, '-silent'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Storing the result
    output = result.stdout
    error = result.stderr
    if (output):
        with open('Subfinder_subs.txt', 'a') as file:
            file.write(output)
    if (error):
        print("Error:", error)
    print("findomain running :")
    result2 = subprocess.run(['findomain', '-q', '-t', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # print(result2)
    output2 = result2.stdout
    error2 = result2.stderr
    if (output2):
        with open('findomain_subs.txt', 'a') as file:
            file.write(output)
    if (error2):
        print("Error:", error)
collect_subdomains()
# function for extract all subdomain with all file and give all_Subdomains.txt
def all_Subdomains():
    result_all = subprocess.run(['cat *.txt | sort | uniq > all_Subdomains.txt'])
all_Subdomains()
