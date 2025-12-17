import os
import re
from pathlib import Path
from git import Repo

def remoteBranchCheckNoCheckout(repoPath, regPattern):
    try:
        repo = Repo(repoPath)
        origin = repo.remotes.origin
        #print(origin.url)
        #branchCount = len(list(repo.branches))
        #print(f" Branch count for {repoPath}: {branchCount}")

        origin.fetch(prune=True)
        branchCount = len(list(origin.refs))
        print(f" Branch count for {repoPath}: {branchCount}")
    except Exception as e:
        #print(f"Error fetching {e}")
        print(type(e), e)
        return {}
        
    pattern = re.compile(regPattern, re.IGNORECASE | re.MULTILINE)

    results = {}
    if branchCount < 500:
        for ref in origin.refs:
            
            try:
                branch = ref.remote_head
                print(f"fetching files for branch {branch} | Repo: {repo}")
                files = repo.git.ls_tree('-r', '--name-only', ref.name).splitlines()
            except Exception as e:
                print(f"Error {e} listing files | branch {branch} | repo {repoPath}")
                continue


            fileCount = len(files)
            if fileCount > 10000:
                with open('branchTooManySkip-agent-framework.txt', 'a') as skipFile:
                    skipFile.write(f"Skipping scan for repo {repoPath} due to large file count ({fileCount}) in branch {branch}\n")
                print(f"Skipping repo {repoPath} — branch {branch} has {fileCount} files .")
                continue
                #return {}

            matchOnBranch = []
            for path in files:
                
                try:
                    print(f"In {repoPath}: getting content: {path} ")
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
                #return results
    else:
        with open ('branchTooManySkip-agent-framework.txt', 'a') as skipFile:
            skipFile.write(f"Skipping branch scan for {repoPath} due to high branch count: {branchCount}\n")
        #print(f"Skipping branch scan for {repoPath} due to high branch count: {branchCount}")

    return results


if __name__ == "__main__":
    repoPath = "<path to repo>"
    #repoPath = Path('<path to repo for Windows>')
    
    #regPattern = r"(Bearer\s+[A-Za-z0-9\.\-_]+|SECRET_KEY = \S{10,}|AccountKey=\S{10,}|AKIA[0-9A-Z]{16})"
    #regPattern = r'(Azure_Storage_(?:AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken)[^\n]+|SECRET_KEY = .{10,}|AKIA[0-9A-Z]{16}|ClientSecret"\svalue=.+|(?:AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)=\S{10,}|AccountKey=\S{10,}|secret_key_base:\s.[A-Za-z0-9_.-]{12,}|secret(?:\s|:|=).+[A-Za-z0-9_.-]{12,}|Bearer\s.\S{11,}| (Refresh_Token|REFRESH_TOKEN|refresh_token)\s.\S{11,}|api[_-](?:key|token)(?:\:|=).[A-Za-z0-9_.-]{10,}|-----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----|(?:password|Password|passwd|pwd)\s*[:=]\s*[\"\'][^\s\"\']{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'
    regPattern = r'(Azure_Storage_(?:AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken)[^\n]+|SECRET_KEY(\s|:|=){0,8}(["\'`])(.{10,})(["\'`])|AKIA[0-9A-Z]{16}|ClientSecret"\svalue=(?!("ENTER_YOUR_SECRET")).+|(?:AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)=\S{10,}|AccountKey=\S{10,}|secret_key_base:\s.[A-Za-z0-9_.-]{12,}|secret(\s|:|=){0,8}(["\'`])(?!(YOUR_CLIENT_SECRET|ENTER_YOUR_SECRET|value="ENTER_YOUR_SECRET"|\svalue\=\"ENTER_YOUR_SECRET\")) (.{8,})(["\'`])|Bearer\s.\S{11,}| (Refresh_Token|REFRESH_TOKEN|refresh_token)\s.\S{11,}|api[_-](?:key|token)(?:\:|=).[A-Za-z0-9_.-]{10,}|Key" value=(["\'])(?:[A-Za-z0-9=\/_\-\+]{10,})|-----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----|(?:password|Password|passwd|pwd)\s*[:=]\s*[\"\'][^\s\"\']{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'
    
    with open ('agentFrameworkCred.txt', 'w',encoding='utf-8', errors='ignore') as credFile:
        for root, dirs, files in os.walk(repoPath):
            for dir in dirs:
                
                repoPath1 = os.path.join(root, dir)

                hits = remoteBranchCheckNoCheckout(repoPath1,regPattern)
                #print(hits)

                for branch, matches in hits.items():
                    #print(f"Branch: {dir}/{branch}")
                    for item in matches:
                        for val in item['matches']:
                            print(f"""Writing to file...""")
                            credFile.write(f"""===========================================================================================================================================================================================
In Repo {dir} under Branch {branch}
        Found in File: {item['path']}
            Match: {val}
""")

