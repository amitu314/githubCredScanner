import requests
import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
from git import Repo


def gitRepoUnderAcc(accName):
    #print('in function')
    token = os.environ.get('GITHUB_TOKEN')
    
    headers = {
    "Authorization": f"Bearer {token}"
}
    repoName = []
    pageNo = 1
    while True:
        accountURL = 'https://api.github.com/orgs/'+str(accName)+'/repos'
        #print(accountURL)
        param = {'per_page': 100, 'page': pageNo}
        response =  requests.get(accountURL, headers=headers, params=param)
        #print(response.status_code)
        if response.status_code == 200 and pageNo <100:
            repoData = response.json()
            pageNo += 1
            #gitRepoUnderAcc(accName)
            repoName.extend(repoData)
            #print(pageNo)
            #return repoName
            #repoNames = [repo['name'] for repo in repoData]
            #return repoNames
        else:
            break
    return repoName


def getRepo(repos,acc):
    
    for repo in repos:
        repourl = f"https://github.com/{acc}/{repo['name']}.git"
        #print(repourl)
        try:
            if os.path.exists('./'+acc+'/'+repo['name']):
                print(f"Repository {repo['name']} already exists. Skipping clone.")
            else:
                print(f"Cloning repository: {repo['name']}")
                Repo.clone_from(repourl, './'+acc+'/'+repo['name'])
        except Exception as e:
            print(f"{e}")


if __name__ == "__main__":
    
    accountName = input("Enter the GitHub account name: ")
    repositories = gitRepoUnderAcc(accountName)
    #print(repositories)
    getRepo(repositories,accountName)

    
