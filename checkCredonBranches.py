import os
import re
from pathlib import Path
from git import Repo

def remoteBranchCheckNoCheckout(repoPath, regPattern):
    repo = Repo(repoPath)
    origin = repo.remotes.origin
    #print(origin.url)
    try:
        origin.fetch()
    except Exception as e:
        print(f"Error fetching {e}")
        
    pattern = re.compile(regPattern, re.IGNORECASE | re.MULTILINE)

    results = {}
    for ref in origin.refs:
        branch = ref.remote_head
        try:
            files = repo.git.ls_tree('-r', '--name-only', ref.name).splitlines()
        except Exception as e:
            print(f"Error {e} listing files | branch {branch} | repo {repoPath}")
            continue
        matchOnBranch = []
        for path in files:
            
            try:
                content = repo.git.show(f"{ref.name}:{path}")
            except Exception as e:
                print(f"Error {e} reading file {path} | branch {branch} | repo {repoPath}")
                continue

            matches = list(pattern.findall(content))
            if matches:
                matchOnBranch.append({"path": path, "matches": matches})

        if matchOnBranch:
            #print(matchOnBranch)
            results[branch] = matchOnBranch
            #return matchOnBranch

    return results


if __name__ == "__main__":
    repoPath = "./<your path to the repo/"
    
    #regPattern = r"(Bearer\s+[A-Za-z0-9\.\-_]+|SECRET_KEY = \S{10,}|AccountKey=\S{10,}|AKIA[0-9A-Z]{16})"
    regPattern = r'(Azure_Storage_(?:AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken)[^\n]+|SECRET_KEY = .{10,}|ClientSecret"\svalue=.+|(?:AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)=\S{10,}|AccountKey=\S{10,}|secret_key_base:\s.[A-Za-z0-9_.-]{12,}|secret(?:\s|:|=).+[A-Za-z0-9_.-]{12,}|Bearer\s.\S{11,}| (Refresh_Token|REFRESH_TOKEN|refresh_token)\s.\S{11,}|api[_-](?:key|token)(?:\:|=).[A-Za-z0-9_.-]{10,}|-----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----|(?:password|Password|passwd|pwd)\s*[:=]\s*[\"\'][^\s\"\']{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'
    with open ('MSGraphCreds.txt', 'w',encoding='utf-8', errors='ignore') as credFile:
        for root, dirs, files in os.walk(repoPath):
            for dir in dirs:
                
                repoPath1 = os.path.join(root, dir)
                hits = remoteBranchCheckNoCheckout(repoPath1,regPattern)
                #print(hits)

                for branch, matches in hits.items():
                    #print(f"Branch: {dir}/{branch}")
                    for item in matches:
                        for val in item['matches']:
                            credFile.write(f"""===========================================================================================================================================================================================
In Repo {dir} under Branch {branch}
        Found in File: {item['path']}
            Match: {val}
""")

                            '''print(f"""In Repo {dir} 
    under Branch {branch} 
        Found in File: {item['path']}
            Match: {val}
""")'''
