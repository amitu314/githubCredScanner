import os
import re

def walkDir():
    path = './<Enter your Directory for OS walking. This directory is where all the repos from cloneRepoOrgAcc script>/'
    
    print(f"checking path: {path}")
    #regPattern = r'(ClientSecret\"\svalue\=.+|AccountKey\=.\S{10,}|secret_key_base\:\s.[a-zA-Z0-9_.-]{12,}|secret(\s|\:|\=).+[a-zA-Z0-9_.-]{12,}|Bearer\s.\S{11,}|(api[_-](key|token)(\:|\=).[a-zA-Z0-9_.-]{10,}))'
    #regPattern = r'(ssh-rsa\s+[A-Za-z0-9+/=]+|BEGIN\s(RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY|(password|passwd|pwd|Password|PASSWORD)(\s|\:|\=).{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'
    regPattern = r'''
(
    (mongodb|postgres|mysql|jdbc|redis|ftp|smtp)[\s_\-=:][a-zA-Z0-9+\=.-_]{10,}|
    (Azure_Storage_(AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken).+)|
    (ClientSecret\"\svalue\=.+)|
    ((AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)\=.\S{10,})|
    (AccountKey\=.\S{10,})|
    (secret_key_base\:\s.[a-zA-Z0-9_.-]{12,})|
    (secret(\s|\:|\=).+[a-zA-Z0-9_.-]{12,})|
    (Bearer\s.\S{11,})|
    (api[_-](key|token)(\:|\=).[a-zA-Z0-9_.-]{10,}))|
    api[_-](key|token)(\:|\=).[a-zA-Z0-9_.-]{10,}|
    (ssh-rsa\s+[A-Za-z0-9+/=]+) |
    (-----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----) |
    ((password|passwd|pwd|Password|PASSWORD)\s*[:=]\s*["']?[^\s"']{8,}) |
    (eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}) 
)
'''
    for root, dirs, files in os.walk(path, topdown=True):
        for file in files:
            #print(os.path.join(root, file))
            with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    content = f.read()
                    match = re.findall(regPattern, content)
                    if match:
                        print(f"Found in file: {os.path.join(root, file)}| Matches: {match}")
                except Exception as e:
                    print(f"Error reading file {file}: {e}")

if __name__ == "__main__":
    walkDir()
